# Installition

First of all, install Zinc: [https://github.com/zpreview/public/releases](https://github.com/zpreview/public/releases).

```sh
$ cd 42zk/circuits/twin
$ zargo proof-check
```

# How get proof?

Open `./data/witness.json`, fill in datas, and run flowing cmd:

```
$ zargo prove                # --------------> hex proof data
$ python read_public_data.py # --------------> input hash and output hash
$ cat verifying-key.txt      # --------------> verifying key
```
