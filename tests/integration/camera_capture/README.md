# Camera transport integration

Build with `./tests/integration/build-camera-capture.sh`, then run
`python3 tests/integration/test_camera_capture.py` from the repository root.
The test uses emulator user networking and synthetic credentials/images. No
physical board, TAP, enrollment or private camera configuration is used.

It exercises the production ESP-IDF HTTP client/deadline adapter with HTTP
Basic/Digest authentication, SOAP UsernameToken digest, profile fallback,
chunked responses, body bounds, incomplete bodies, redirect refusal, stalls
and cancellation. A loopback RTSP fixture verifies Digest qop=auth, session
setup, TCP interleaving and RTP/JPEG reconstruction through the production
socket adapter. Synthetic entropy checks transport framing only; native tests
verify a public JPEG fixture byte for byte. Private C211 captures were also
decoded independently on the host; they are never repository fixtures.
