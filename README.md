Usage
=====

Setup phase:
```
python3 -m venv venv
source ./venv/bin/activate
pip install -r requirements.txt
```

Ensure a snapshot is available in `execution-data`, for instance `https://snapshots.ethpandaops.io/mainnet/nethermind/23360000/snapshot.tar.zst`. This example downloads for block 23360000 the snapshot for Nethermind.

(see https://ethpandaops.io/data/snapshots/?snapshot-network=quickstart):

```
docker run --rm -it \
  -e ETH_NETWORK=mainnet \
  -e ETH_CLIENT=nethermind \
  -v $PWD:/data \
  --entrypoint "/bin/sh" \
  alpine -c \
  'apk add --no-cache wget curl tar zstd && \
  export BLOCK_NUMBER=23360000 && \
  echo \"Downloading snapshot for block number: $BLOCK_NUMBER\" && \
  wget --tries=0 --retry-connrefused -O - https://snapshots.ethpandaops.io/$ETH_NETWORK/$ETH_CLIENT/$BLOCK_NUMBER/snapshot.tar.zst | \
  tar -I zstd -xvf - -C /data'
```