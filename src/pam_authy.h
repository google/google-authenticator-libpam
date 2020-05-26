/*
 * Google authenticator extension for Authy push notifications
 *
 * Copyright 2020 Krzysztof Olejarczyk
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef AUTHY_H
#define AUTHY_H

typedef enum {
	AUTHY_OK = 0,
	AUTHY_LIB_ERROR,
	AUTHY_CONN_ERROR,
	AUTHY_APPROVED,
	AUTHY_DENIED,
	AUTHY_PENDING,
	AUTHY_EXPIRED,
	AUTHY_NO_SUPPORT,
} authy_rc_t;

authy_rc_t authy_login(pam_handle_t *pamh, long authy_id, char *api_key, int timeout);

#endif /* AUTHY_H */
