import json

with open('./data/public-data.json') as f:
    data = json.load(f)

s = ["0" for _ in range(256)]

for i, e in enumerate(data['input_amount_hash']):
    if e:
        f = "1"
    else:
        f = "0"
    s[i] = f


print("i", hex(eval('0b' + ''.join(s)))[2:])


for i, e in enumerate(data['output_amount_hash']):
    if e:
        f = "1"
    else:
        f = "0"
    s[i] = f

print("o", hex(eval('0b' + ''.join(s)))[2:])
