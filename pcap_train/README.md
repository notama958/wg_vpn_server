# Set up Wireguard VPN server

## 1. Install WireGuard on the server

```bash
sudo apt update
sudo apt install -y wireguard wireguard-tools
```

## 2. Generate server and peer keys

```bash
wg genkey | sudo tee server_private.key | wg pubkey | sudo tee server_public.key
```

Repeat for each client/peer (laptop, phone, ...):

```bash
wg genkey | tee peer_private.key | wg pubkey > peer_public.key
```

Put the server's private key and each peer's public key into [`../conf/wg0.conf`](../conf/wg0.conf)
(see `PrivateKey` under `[Interface]` and `PublicKey` under each `[Peer]`).

## 3. Bring up the tunnel

```bash
sudo cp ../conf/wg0.conf /etc/wireguard/wg0.conf
sudo wg-quick up wg0
sudo wg show
```

## 4. Configure WireGuard clients (Windows/macOS/phone)

Fill in the client config using the peer's own private key, a unique tunnel IP, and the
server's public key + endpoint (`<server-ip>:51820`, e.g. `192.168.0.253:51820`):

```ini
[Interface]
PrivateKey = <peer_private_key>
Address = 10.66.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = <server_public_key>
AllowedIPs = 0.0.0.0/0
Endpoint = 192.168.0.253:51820
PersistentKeepalive = 25
```

Import this into the official WireGuard app and activate the tunnel.

## 5. Verify the connection

From the client, confirm traffic is routed through the tunnel:

```bash
# On the server
sudo wg show   # expect a recent "latest handshake" for the peer

# On the client
ping 10.66.0.1
curl ifconfig.me   # should return the VPN server's public IP
```

## 6. Set up the Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 7. Capture labelled pcap files

From the **repository root** (with the venv active), capture one pcap per traffic class on
the `wg0` interface while generating the corresponding traffic from a connected client
(browse the web, watch a video, make a VoIP call, download a large file):

```bash
mkdir -p pcaps
sudo tcpdump -i wg0 'not port 22' -w pcaps/web.pcap     # while browsing the web
sudo tcpdump -i wg0 'not port 22' -w pcaps/voip.pcap    # while on a VoIP/video call
sudo tcpdump -i wg0 'not port 22' -w pcaps/bulk.pcap    # while downloading a large file
sudo tcpdump -i wg0 'not port 22' -w pcaps/video.pcap   # while streaming video
```

The label used for training is taken from each pcap's filename (without the `.pcap`
extension), so `pcaps/<label>.pcap` — matching [`pcap_parser.py`](./pcap_parser.py)'s
`PCAP_DIR = "./pcaps"` default.

## 8. Train the model

Run from the repository root so `./pcaps` resolves correctly:

```bash
./pcap_train/train.py
```

This parses every pcap in `pcaps/` into sliding-window features (see
[`pcap_parser.py`](./pcap_parser.py)), trains a `RandomForestClassifier`, and exports
`model/model.onnx` for [`server_app`](../main.cpp) to load.

Example output:

```
(.venv) root:~/wg_vpn_server $ ./pcap_train/train.py
Processing web ...
Extracted 4368 windows from web
Processing voip ...
Extracted 724 windows from voip
Processing bulk ...
Extracted 21135 windows from bulk
Processing video ...
Extracted 40163 windows from video

Confusion matrix:
 [[ 6135     5     0   201]
 [    5 11996     2    46]
 [    0     0   212     5]
 [  392    40     0   878]]

               precision    recall  f1-score   support

        bulk       0.94      0.97      0.95      6341
       video       1.00      1.00      1.00     12049
        voip       0.99      0.98      0.98       217
         web       0.78      0.67      0.72      1310

    accuracy                           0.97     19917
   macro avg       0.93      0.90      0.91     19917
weighted avg       0.96      0.97      0.96     19917
```

More labelled data for `voip` and `web` (currently the smallest/weakest classes) should
improve accuracy further.
