Dependencies/Requirements
*************************
- Python 3.8 or newer (Python 3.10+ recommended)
- cryptography package
  Install with:
    python3 -m pip install --user cryptography

How to Run (On single machine)
******************************
1. Open two terminal windows.

2. Start Alice (terminal 1)
   (RSA-only variant)
   python3 full_peer_rsa.py --listen 127.0.0.1:9001 --name Alice

3. Start Bob (terminal 2)
   python3 full_peer_rsa.py --listen 127.0.0.1:9002 --name Bob

4. Connect Bob to Alice (type in Bob's terminal):
   connect 127.0.0.1:9001

5. Send messages:
   From Bob:
     /tell Alice Hello Alice
     /all classroom1 Hello everyone
     /file Alice example_file.txt
   From Alice:
     /tell Bob Hi Bob

6. Check downloads/ directory to find received file saved under downloads/<sender_name>/.

