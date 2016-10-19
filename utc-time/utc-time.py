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
import time
t = time.time()
u = time.gmtime(t)
s = time.strftime('%a, %e %b %Y %T GMT', u)
print 'Content-Type: text/javascript'
print 'Cache-Control: no-cache'
print 'Date: ' + s
print 'Expires: ' + s
print ''
print 'var timeskew = new Date().getTime() - ' + str(t*1000) + ';'
