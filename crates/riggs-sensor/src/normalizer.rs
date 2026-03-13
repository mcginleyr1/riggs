use riggs_types::events::RiggsEvent;

pub struct EventNormalizer;

impl EventNormalizer {
    pub fn normalize(event: RiggsEvent) -> RiggsEvent {
        // Stub: pass through for now.
        // Future: ensure storyline IDs are set, timestamps are valid,
        // fields are within expected bounds.
        event
    }
}
