/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator;

public class FoursquareAuthenticatorConstants {

	/*
	 * Private Constructor will prevent the instantiation of this class directly
	 */
	private FoursquareAuthenticatorConstants() {
	}
	//Foursquare authorize endpoint URL.
	public static final String FOURSQUARE_OAUTH_ENDPOINT = "https://foursquare.com/oauth2/authenticate";
	//Foursquare token  endpoint URL.
	public static final String FOURSQUARE_TOKEN_ENDPOINT = "https://foursquare.com/oauth2/access_token";
	//Foursquare user info endpoint URL.
	public static final String FOURSQUARE_USER_INFO_ENDPOINT = "https://api.foursquare.com/v2/users/self?v=";
	//Foursquare connector friendly name.
	public static final String FOURSQUARE_CONNECTOR_FRIENDLY_NAME = "Foursquare";
	//Foursquare connector name.
	public static final String FOURSQUARE_CONNECTOR_NAME = "Foursquare";
	//The oauth access token.
	public static final String FOURSQUARE_OAUTH2_ACCESS_TOKEN_PARAMETER = "oauth_token";
	//The access token.
	public static final String ACCESS_TOKEN = "access_token";
	//The profile version.
	public static final String PROFILE_VERSION = "profileVersion";
	//The oauth2 token URL.
	public static final String OAUTH2_TOKEN_URL = "OAUTH2TokenUrl";
	//The ID of the user.
	public static final String ID = "id";
	// First name of the user.
	public static final String FIRST_NAME = "firstName";
	//Last name of the user.
	public static final String LAST_NAME = "lastName";
	//User contact.
	public static final String CONTACT = "contact";
	//User Email.
	public static final String EMAIL = "email";
	//User BIO.
	public static final String BIO = "bio";
	//user gender.
	public static final String GENDER = "gender";
	//User relationship.
	public static final String RELATIONSHIP = "relationship";
	//User home city.
	public static final String HOME_CITY = "homeCity";
	//CanonicalUrl of the user.
	public static final String CANONICAL_URL = "canonicalUrl";
	//Response.
	public static final String RESPONSE = "response";
	//The user.
	public static final String USER = "user";
	//The claim dialect URI.
	public static final String CLAIM_DIALECT_URI = "http://wso2.org/foursquare/claims";
	//The Http get method.
	public static final String HTTP_GET_METHOD = "GET";
	//Constant for connection time out.
	public static final int CONNECTION_TIMEOUT_VALUE = 15000;
	//Constant for read time out.
	public static final int READ_TIMEOUT_VALUE = 15000;
}