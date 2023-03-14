#!/bin/bash

generate_post_data()
{
  cat <<EOF
{
  "username": "yy@gmail.com",
  "responseType": "ssh",
  "enpoint": "bijay",
  "group": "muthu"
}
EOF
}

echo "hello , Starting the Assertion"



curl -i \
-H "Accept: application/json" \
-H "Content-Type:application/json" \
--connect-timeout 10 \
-m 10 \
-X POST --data "$(generate_post_data)" "https://api.did.kloudlearn.com/authnull0/api/v1/authn/do-authentication" 
