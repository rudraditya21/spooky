use std::{
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use hyper::body::{Body, Frame};
use tokio::sync::mpsc;

/// A streaming HTTP body backed by a tokio mpsc channel.
/// The quiche Data handler sends chunks through the sender;
/// hyper reads them from the receiver as the H2 request body.
pub struct ChannelBody {
    rx: mpsc::Receiver<Bytes>,
}

impl ChannelBody {
    pub fn channel(buffer: usize) -> (mpsc::Sender<Bytes>, Self) {
        let (tx, rx) = mpsc::channel(buffer);
        (tx, Self { rx })
    }
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(chunk)) => Poll::Ready(Some(Ok(Frame::data(chunk)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
