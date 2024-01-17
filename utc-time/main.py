#!/usr/bin/env python
# Copyright 2011 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# gcloud app deploy --project utc-time2
import time
from flask import Flask, make_response, request
app = Flask(__name__)

@app.route('/')
def root():
    t = time.time()
    u = time.gmtime(t)
    s = time.strftime('%a, %e %b %Y %T GMT', u)

    resp = make_response('var timeskew = new Date().getTime() - ' + str(t*1000) + ';')
    resp.headers['Content-Type'] = 'text/javascript'
    resp.headers['Cache-Control'] = 'no-cache'
    resp.headers['Date'] = s
    resp.headers['Expires'] = s
    return resp

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)
