# Riggs: ML Pipeline

## Overview

Riggs performs all ML inference on-device. No event data is sent to a cloud
service for classification. This design ensures protection works without
network connectivity and that sensitive endpoint telemetry never leaves the
machine.

Two model types are deployed:

1. **Static model** — analyzes file features to produce a malicious/benign
   probability
2. **Behavioral model** — analyzes event sequences to produce a threat score

Both models are ONNX format, executed via the `ort` crate (ONNX Runtime
bindings) with a fallback to `tract-onnx` (pure Rust, no native dependencies).

ML code lives in two crates:
- `riggs-static-ai` — static file analysis
- `riggs-behavioral-ai` — behavioral sequence analysis

## Model Storage

```
models/
  static/
    v1/
      model.onnx          # ONNX model file
      features.json        # feature vector schema
      metadata.json        # model version, training date, metrics
      thresholds.json      # decision thresholds per class
    v2/
      ...
  behavioral/
    v1/
      model.onnx
      features.json
      metadata.json
      thresholds.json
    v2/
      ...
  active.toml              # points to active model versions
```

### active.toml

```toml
[static]
version = "v1"
path = "models/static/v1/model.onnx"

[behavioral]
version = "v1"
path = "models/behavioral/v1/model.onnx"
```

Model updates are deployed by:
1. Copying the new model directory to `models/static/v2/` (or wherever).
2. Updating `active.toml` to point to the new version.
3. The daemon detects the change via `notify` and hot-reloads the model.
4. The old model remains on disk for rollback.

## Static Model

### Purpose

The static model classifies files as malicious or benign based on their
structural and content features, without executing them. It catches known
malware families, packed/encrypted binaries, and structurally anomalous
executables.

### Feature Extraction

Feature extraction runs in `riggs-static-ai` using `goblin` for binary
parsing. The feature vector is fixed-size (256 floats) to match the model
input dimension.

#### Mach-O Features (Primary Target)

```rust
pub fn extract_macho_features(data: &[u8]) -> Result<StaticFeatureVector, FeatureError> {
    let macho = goblin::mach::MachO::parse(data, 0)?;

    let mut features = [0.0f32; 256];
    let mut idx = 0;

    // Header features (indices 0-15)
    features[idx] = macho.header.cputype as f32; idx += 1;
    features[idx] = macho.header.cpusubtype as f32; idx += 1;
    features[idx] = macho.header.filetype as f32; idx += 1;
    features[idx] = macho.header.ncmds as f32; idx += 1;
    features[idx] = macho.header.sizeofcmds as f32; idx += 1;
    features[idx] = macho.header.flags as f32; idx += 1;

    // Segment features (indices 16-79): count, sizes, permissions
    features[idx] = macho.segments.len() as f32; idx += 1;
    for seg in macho.segments.iter() {
        features[idx] = seg.vmsize as f32; idx += 1;
        features[idx] = seg.filesize as f32; idx += 1;
        features[idx] = (seg.maxprot & 0x7) as f32; idx += 1;
        features[idx] = (seg.initprot & 0x7) as f32; idx += 1;
        if idx >= 80 { break; }
    }
    idx = 80;

    // Import features (indices 80-143)
    let imports = macho.imports()?;
    features[idx] = imports.len() as f32; idx += 1;
    // Count imports per dylib
    let mut dylib_counts: HashMap<&str, usize> = HashMap::new();
    for imp in &imports {
        *dylib_counts.entry(imp.dylib).or_default() += 1;
    }
    features[idx] = dylib_counts.len() as f32; idx += 1;
    // Suspicious import indicators
    features[idx] = has_import(&imports, "dlopen") as u8 as f32; idx += 1;
    features[idx] = has_import(&imports, "ptrace") as u8 as f32; idx += 1;
    features[idx] = has_import(&imports, "fork") as u8 as f32; idx += 1;
    features[idx] = has_import(&imports, "exec") as u8 as f32; idx += 1;
    features[idx] = has_import(&imports, "mprotect") as u8 as f32; idx += 1;
    features[idx] = has_import(&imports, "mmap") as u8 as f32; idx += 1;
    idx = 144;

    // Entropy features (indices 144-175): per-section entropy
    for (i, section) in macho.segments.sections().flatten().enumerate() {
        if idx >= 176 { break; }
        let section_data = &data[section.offset as usize..
            (section.offset as usize + section.size as usize).min(data.len())];
        features[idx] = shannon_entropy(section_data); idx += 1;
    }
    idx = 176;

    // String features (indices 176-207)
    let string_stats = extract_string_stats(data);
    features[idx] = string_stats.total_strings as f32; idx += 1;
    features[idx] = string_stats.avg_length as f32; idx += 1;
    features[idx] = string_stats.url_count as f32; idx += 1;
    features[idx] = string_stats.ip_count as f32; idx += 1;
    features[idx] = string_stats.path_count as f32; idx += 1;
    features[idx] = string_stats.registry_count as f32; idx += 1;
    features[idx] = string_stats.suspicious_api_count as f32; idx += 1;
    idx = 208;

    // Size/ratio features (indices 208-223)
    features[idx] = data.len() as f32; idx += 1;
    features[idx] = shannon_entropy(data); idx += 1;
    // code-to-data ratio
    let text_size = find_section_size(&macho, "__TEXT", "__text");
    let data_size = find_section_size(&macho, "__DATA", "__data");
    features[idx] = if data_size > 0 { text_size as f32 / data_size as f32 } else { 0.0 };
    idx += 1;

    // Signing features (indices 224-239)
    features[idx] = macho.code_signature.is_some() as u8 as f32; idx += 1;
    // ... additional signing fields

    // Reserved (indices 240-255) for future features
    // Leave as 0.0

    Ok(StaticFeatureVector { features })
}
```

#### ELF Features

Similar extraction using `goblin::elf::Elf`, adapted for ELF-specific
structures (section headers, dynamic symbols, GNU notes, interpreter).

#### PE Features (Future)

PE feature extraction will use `goblin::pe::PE` for import tables, resources,
authenticode signatures, and section characteristics.

### Feature Normalization

Raw features are normalized before inference:

```rust
pub fn normalize_features(features: &mut [f32; 256], schema: &FeatureSchema) {
    for (i, feature) in features.iter_mut().enumerate() {
        let norm = &schema.normalizations[i];
        match norm.method {
            NormMethod::MinMax => {
                *feature = (*feature - norm.min) / (norm.max - norm.min);
                *feature = feature.clamp(0.0, 1.0);
            }
            NormMethod::ZScore => {
                *feature = (*feature - norm.mean) / norm.std_dev;
            }
            NormMethod::Log => {
                *feature = (*feature + 1.0).ln();
            }
            NormMethod::None => {}
        }
    }
}
```

The normalization parameters are stored in `features.json` alongside the model
and are versioned together.

### ONNX Inference

```rust
pub struct StaticModel {
    session: ort::Session,
    feature_schema: FeatureSchema,
    thresholds: Thresholds,
}

impl StaticModel {
    pub fn load(model_dir: &Path) -> Result<Self, ModelError> {
        let model_path = model_dir.join("model.onnx");
        let session = ort::Session::builder()?
            .with_optimization_level(ort::GraphOptimizationLevel::Level3)?
            .with_intra_threads(1)?  // single-threaded per inference
            .commit_from_file(&model_path)?;

        let feature_schema = load_json(model_dir.join("features.json"))?;
        let thresholds = load_json(model_dir.join("thresholds.json"))?;

        Ok(Self { session, feature_schema, thresholds })
    }

    pub fn predict(&self, features: &StaticFeatureVector) -> Result<StaticPrediction, ModelError> {
        let mut normalized = features.features;
        normalize_features(&mut normalized, &self.feature_schema);

        let input = ort::Value::from_array(([1, 256], normalized.as_slice()))?;
        let outputs = self.session.run(ort::inputs![input]?)?;

        let probabilities: &[f32] = outputs[0].extract_tensor()?;
        let malicious_prob = probabilities[1]; // index 1 = malicious class

        Ok(StaticPrediction {
            malicious_probability: malicious_prob,
            confidence: (malicious_prob - 0.5).abs() * 2.0, // 0.0 at boundary, 1.0 at extremes
            family_scores: extract_family_scores(&outputs, &self.thresholds),
        })
    }
}
```

### Thresholds

Decision thresholds are separate from the model to allow tuning without
retraining:

```json
{
    "malicious_threshold": 0.65,
    "suspicious_threshold": 0.35,
    "family_thresholds": {
        "ransomware": 0.7,
        "trojan": 0.6,
        "adware": 0.5,
        "cryptominer": 0.6
    }
}
```

- Score > `malicious_threshold` → Disposition::Malicious
- Score > `suspicious_threshold` → Disposition::Suspicious
- Score <= `suspicious_threshold` → Disposition::Clean

## Behavioral Model

### Purpose

The behavioral model detects threats based on runtime behavior patterns. It
catches living-off-the-land attacks, fileless malware, and slow-and-low
operations that static analysis cannot see.

### Feature Extraction

Behavioral features are extracted from the event stream per storyline:

```rust
pub struct BehavioralFeatureExtractor {
    window_size: usize,         // max events in window (default 100)
    window_duration: Duration,  // max time span (default 60s)
}

impl BehavioralFeatureExtractor {
    pub fn extract(
        &self,
        events: &[EventEnvelope],
    ) -> BehavioralFeatureVector {
        let mut features = BehavioralFeatureVector::default();

        // Event type counts
        features.process_event_count = count_type(events, EventType::Process);
        features.file_event_count = count_type(events, EventType::File);
        features.network_event_count = count_type(events, EventType::Network);

        // Process behavior
        features.unique_child_processes = count_unique_children(events);
        features.privilege_escalation_count = count_priv_esc(events);

        // File behavior
        features.unique_file_paths_written = count_unique_writes(events);
        features.entropy_of_written_data = avg_write_entropy(events);

        // Network behavior
        features.unique_remote_ips = count_unique_remote_ips(events);
        features.dns_query_count = count_dns_queries(events);
        features.network_bytes_ratio = compute_bytes_ratio(events);

        // Temporal features (32 floats)
        features.temporal_features = extract_temporal(events);

        // Event rate burst detection
        features.max_event_burst_rate = compute_burst_rate(events);

        // Sequence embedding (64 floats)
        // Event types are mapped to integers, then the sequence is
        // run through a learned embedding lookup
        features.sequence_embedding = compute_sequence_embedding(events);

        features
    }
}
```

#### Temporal Feature Extraction

The 32 temporal features capture time-series patterns:

```rust
fn extract_temporal(events: &[EventEnvelope]) -> [f32; 32] {
    let mut temporal = [0.0f32; 32];

    // Inter-event time statistics (indices 0-7)
    let deltas: Vec<f64> = events.windows(2)
        .map(|w| (w[1].timestamp - w[0].timestamp).num_milliseconds() as f64)
        .collect();

    temporal[0] = mean(&deltas) as f32;
    temporal[1] = std_dev(&deltas) as f32;
    temporal[2] = min_val(&deltas) as f32;
    temporal[3] = max_val(&deltas) as f32;
    temporal[4] = median(&deltas) as f32;
    temporal[5] = skewness(&deltas) as f32;
    temporal[6] = kurtosis(&deltas) as f32;
    temporal[7] = deltas.len() as f32;

    // Event rate over time buckets (indices 8-23)
    // Divide the window into 16 equal time buckets and count events per bucket
    let buckets = bucket_events(events, 16);
    for (i, count) in buckets.iter().enumerate() {
        temporal[8 + i] = *count as f32;
    }

    // Event type transition probabilities (indices 24-31)
    // How often does Process follow File, Network follow DNS, etc.
    let transitions = compute_type_transitions(events);
    for (i, prob) in transitions.iter().take(8).enumerate() {
        temporal[24 + i] = *prob;
    }

    temporal
}
```

#### Sequence Embedding

The 64-float sequence embedding compresses the event type sequence into a
dense vector. This is a learned embedding from the training pipeline:

```rust
fn compute_sequence_embedding(events: &[EventEnvelope]) -> [f32; 64] {
    // Map event types to integers
    let sequence: Vec<u32> = events.iter().map(|e| match &e.event_type {
        EventType::Process(_) => 0,
        EventType::File(_) => 1,
        EventType::Network(_) => 2,
        EventType::DNS(_) => 3,
        EventType::Auth(_) => 4,
        EventType::Kernel(_) => 5,
        EventType::Registry(_) => 6,
    }).collect();

    // The embedding table is loaded from the model directory
    // It maps each event type integer to a 64-float embedding
    // The final embedding is the mean of all event embeddings in the sequence
    let embedding_table: &[[f32; 64]; 7] = &EMBEDDING_TABLE;

    let mut result = [0.0f32; 64];
    for &event_type_id in &sequence {
        let embedding = &embedding_table[event_type_id as usize];
        for (i, val) in embedding.iter().enumerate() {
            result[i] += val;
        }
    }

    let count = sequence.len().max(1) as f32;
    for val in result.iter_mut() {
        *val /= count;
    }

    result
}
```

### ONNX Inference

```rust
pub struct BehavioralModel {
    session: ort::Session,
    feature_schema: FeatureSchema,
    thresholds: Thresholds,
}

impl BehavioralModel {
    pub fn predict(
        &self,
        features: &BehavioralFeatureVector,
    ) -> Result<BehavioralPrediction, ModelError> {
        let flat = features.to_flat_array(); // ~160 floats total
        let input = ort::Value::from_array(([1, flat.len()], flat.as_slice()))?;
        let outputs = self.session.run(ort::inputs![input]?)?;

        let scores: &[f32] = outputs[0].extract_tensor()?;

        Ok(BehavioralPrediction {
            threat_score: scores[0],
            attack_stage: classify_stage(&outputs[1]),
            technique_scores: extract_technique_scores(&outputs[2]),
        })
    }
}
```

### Evaluation Schedule

The behavioral model is not evaluated on every event (too expensive). Instead:

1. **Timer-based**: Every 5 seconds per active storyline.
2. **Threshold-based**: When a storyline accumulates N new events since the
   last evaluation (default N=20).
3. **Trigger-based**: Immediately when a high-priority event occurs (e.g.,
   privilege escalation, unusual network connection).

This amortized approach keeps CPU usage bounded even under high event volume.

## Runtime Fallback

### ort (Primary)

The `ort` crate wraps the official Microsoft ONNX Runtime, which provides
optimized CPU kernels (AVX2/AVX-512 on x86, NEON on ARM).

`ort` is configured with `load-dynamic` feature, meaning the ONNX Runtime
shared library (`libonnxruntime.dylib` / `libonnxruntime.so`) is loaded at
runtime, not linked at compile time. This allows shipping the library
separately or using a system-installed version.

### tract-onnx (Fallback)

If `ort` fails to initialize (missing shared library, unsupported platform),
Riggs falls back to `tract-onnx`:

```rust
pub fn load_model(model_path: &Path) -> Result<Box<dyn ModelRuntime>, ModelError> {
    match ort_runtime::load(model_path) {
        Ok(runtime) => Ok(Box::new(runtime)),
        Err(e) => {
            tracing::warn!("ort failed to load: {e}, falling back to tract");
            let runtime = tract_runtime::load(model_path)?;
            Ok(Box::new(runtime))
        }
    }
}
```

tract is pure Rust with no native dependencies. It is slower (~2-5x) but
works on every platform Rust supports.

## Training Pipeline (Offline)

Model training happens outside of Riggs, on dedicated training infrastructure.
This section documents the training pipeline for completeness.

### Static Model Training

1. **Dataset**: Labeled corpus of malicious/benign executables.
2. **Feature extraction**: Same `extract_*_features()` functions used at
   runtime, ensuring feature parity.
3. **Model architecture**: Gradient-boosted trees (XGBoost) exported to ONNX,
   or a small feedforward neural network (3 hidden layers, ReLU).
4. **Evaluation metrics**: AUC-ROC > 0.99, FPR < 0.1% at 95% TPR.
5. **Export**: Model exported to ONNX format with opset version 17.

### Behavioral Model Training

1. **Dataset**: Labeled event sequences from malware sandboxes and benign
   endpoint telemetry.
2. **Feature extraction**: Same `BehavioralFeatureExtractor` used at runtime.
3. **Model architecture**: LSTM or Transformer encoder, small enough for
   CPU inference (< 10M parameters).
4. **Evaluation metrics**: AUC-ROC > 0.95, FPR < 1% at 90% TPR.
5. **Export**: ONNX format with opset version 17.

### Model Versioning Contract

Every model version directory must contain:

| File             | Purpose                                          |
|------------------|--------------------------------------------------|
| model.onnx       | The ONNX model file                              |
| features.json    | Feature vector schema with normalization params   |
| metadata.json    | Version, training date, dataset info, metrics    |
| thresholds.json  | Decision thresholds per class                    |

The metadata.json includes training metrics so operators can compare model
versions:

```json
{
    "version": "v2",
    "trained_at": "2026-02-01T00:00:00Z",
    "training_samples": 500000,
    "auc_roc": 0.9945,
    "fpr_at_95_tpr": 0.0008,
    "opset_version": 17,
    "input_shape": [1, 256],
    "output_shape": [1, 2],
    "compatible_agent_versions": ">=0.2.0"
}
```

## Metrics

- `riggs_ml_inference_duration_us` — histogram per model type
- `riggs_ml_predictions_total` — counter per model type per disposition
- `riggs_ml_model_version` — info gauge (model version string)
- `riggs_ml_feature_extraction_duration_us` — histogram per model type
- `riggs_ml_fallback_active` — boolean gauge (true if using tract)
