use bytes::{BufMut, BytesMut};
use hyper::{
    header::{HeaderValue, CONTENT_TYPE},
    Body, HeaderMap, Response, StatusCode, Version,
};
use log::warn;
use prost::{EncodeError, Message};
use public::{
    proto::metric,
    queue::DebugSender,
    sender::{SendMessageType, Sendable},
};
use std::net::{IpAddr, SocketAddr};

const CONTENT_TYPE_GRPC: &str = "application/grpc";

#[derive(Debug, PartialEq)]
pub struct SkyWalkingExtra(pub metric::SkyWalkingExtra);

impl Sendable for SkyWalkingExtra {
    fn encode(self, buf: &mut Vec<u8>) -> Result<usize, EncodeError> {
        self.0.encode(buf).map(|_| self.0.encoded_len())
    }

    fn message_type(&self) -> SendMessageType {
        SendMessageType::SkyWalking
    }
}

pub async fn handle_skywalking_request(
    peer_addr: SocketAddr,
    data: Vec<u8>,
    path: &str,
    skywalking_sender: DebugSender<SkyWalkingExtra>,
) -> Response<Body> {
    // Response::builder().status(StatusCode::NOT_FOUND).body(Body::empty())

    let mut skywalking_extra = metric::SkyWalkingExtra::default();
    skywalking_extra.data = data;
    skywalking_extra.peer_ip = match peer_addr.ip() {
        IpAddr::V4(ip4) => ip4.octets().to_vec(),
        IpAddr::V6(ip6) => ip6.octets().to_vec(),
    };

    if let Err(e) = skywalking_sender.send(SkyWalkingExtra(skywalking_extra)) {
        warn!("skywalking_sender failed to send data, because {:?}", e);
    }

    let is_grpc_request = match path {
        "/v3/segments" => false,
        "/skywalking.v3.TraceSegmentReportService/collect"
        | "/skywalking.v3.TraceSegmentReportService/collectInSync" => true,
        _ => false,
    };

    if is_grpc_request {
        // for grpc_request, return empty response to avoid client error
        let mut response_buf = BytesMut::new();
        response_buf.put_u8(0); // grpc not compression
        response_buf.put_u32(0); // grpc data, return length = 0

        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));

        let (mut sender, body) = Body::channel();
        tokio::spawn(async move {
            sender.send_data(response_buf.freeze()).await.unwrap();
            sender.send_trailers(trailers).await.unwrap();
        });

        Response::builder()
            .version(Version::HTTP_2)
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, HeaderValue::from_static(&CONTENT_TYPE_GRPC))
            .body(body)
            .unwrap()
    } else {
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap()
    }
}
