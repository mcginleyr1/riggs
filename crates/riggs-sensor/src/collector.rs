use riggs_platform::PlatformSensor;
use riggs_types::events::RiggsEvent;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::info;

pub struct EventCollector {
    sensor: Box<dyn PlatformSensor>,
    tx: mpsc::Sender<RiggsEvent>,
    task_handle: Option<JoinHandle<()>>,
}

impl EventCollector {
    pub fn new(sensor: Box<dyn PlatformSensor>, tx: mpsc::Sender<RiggsEvent>) -> Self {
        Self {
            sensor,
            tx,
            task_handle: None,
        }
    }

    pub async fn start(&mut self) -> Result<(), riggs_types::errors::RiggsError> {
        let (internal_tx, mut internal_rx) = mpsc::channel::<RiggsEvent>(1024);

        self.sensor.start(internal_tx).await?;
        info!("event collector started");

        let _tx = self.tx.clone();
        let handle = tokio::spawn(async move {
            while let Some(_event) = internal_rx.recv().await {
                todo!("forward event through normalization and send via tx")
            }
            info!("event forwarding loop exited");
        });

        self.task_handle = Some(handle);
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<(), riggs_types::errors::RiggsError> {
        self.sensor.stop().await?;

        if let Some(handle) = self.task_handle.take() {
            handle.abort();
            let _ = handle.await;
        }

        info!("event collector stopped");
        Ok(())
    }
}
