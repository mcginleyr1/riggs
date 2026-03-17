use chrono::Utc;
use riggs_types::events::{ProcessContext, RiggsEvent, StorylineId};
use uuid::Uuid;

pub struct EventNormalizer;

const MAX_STRING_LEN: usize = 4096;

fn truncate(s: &mut String) {
    if s.len() > MAX_STRING_LEN {
        let mut end = MAX_STRING_LEN;
        while !s.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        s.truncate(end);
    }
}

fn normalize_process_context(ctx: &mut ProcessContext) {
    if ctx.storyline_id.0 == Uuid::nil() {
        ctx.storyline_id = StorylineId::new();
    }
    truncate(&mut ctx.name);
    truncate(&mut ctx.path);
    truncate(&mut ctx.cmdline);
    truncate(&mut ctx.user);
}

impl EventNormalizer {
    pub fn normalize(mut event: RiggsEvent) -> RiggsEvent {
        let now = Utc::now();

        match &mut event {
            RiggsEvent::Process(e) => {
                if e.timestamp > now {
                    e.timestamp = now;
                }
                normalize_process_context(&mut e.process_context);
                if let Some(ref mut parent) = e.parent_context {
                    normalize_process_context(parent);
                }
            }
            RiggsEvent::File(e) => {
                if e.timestamp > now {
                    e.timestamp = now;
                }
                normalize_process_context(&mut e.process_context);
            }
            RiggsEvent::Network(e) => {
                if e.timestamp > now {
                    e.timestamp = now;
                }
                normalize_process_context(&mut e.process_context);
            }
            RiggsEvent::Dns(e) => {
                if e.timestamp > now {
                    e.timestamp = now;
                }
                normalize_process_context(&mut e.process_context);
            }
            RiggsEvent::Auth(e) => {
                if e.timestamp > now {
                    e.timestamp = now;
                }
                normalize_process_context(&mut e.process_context);
            }
            RiggsEvent::Kernel(e) => {
                if e.timestamp > now {
                    e.timestamp = now;
                }
                normalize_process_context(&mut e.process_context);
            }
        }

        event
    }
}
