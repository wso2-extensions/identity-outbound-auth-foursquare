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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.util.IdentityIOStreamUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.ProtocolException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Authenticator of Foursquare
 */
public class FoursquareAuthenticator extends OpenIDConnectAuthenticator implements FederatedApplicationAuthenticator {

	public static final long serialVersionUID = -1804204435650065924L;

	private static final Log log = LogFactory.getLog(FoursquareAuthenticator.class);

	/**
	 * Get the authorization endpoint for Foursquare
	 */
	@Override
	protected String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {
		return FoursquareAuthenticatorConstants.FOURSQUARE_OAUTH_ENDPOINT;
	}

	/**
	 * Always return false as there is no ID token in Foursquare OAuth.
	 *
	 * @param authenticatorProperties Authenticator properties.
	 * @return False
	 */
	@Override
	protected boolean requiredIDToken(Map<String, String> authenticatorProperties) {
		return false;
	}

	@Override
	public String getFriendlyName() {
		return FoursquareAuthenticatorConstants.FOURSQUARE_CONNECTOR_FRIENDLY_NAME;
	}

	@Override
	public String getName() {
		return FoursquareAuthenticatorConstants.FOURSQUARE_CONNECTOR_NAME;
	}

	/**
	 * Get configuration properties.
	 *
	 * @return Properties list.
	 */
	@Override
	public List<Property> getConfigurationProperties() {

		List<Property> configProperties = new ArrayList<Property>();

		Property clientId = new Property();
		clientId.setName(OIDCAuthenticatorConstants.CLIENT_ID);
		clientId.setDisplayName("Client Id");
		clientId.setRequired(true);
		clientId.setDescription("Enter Foursquare client identifier value");
		clientId.setDisplayOrder(0);
		configProperties.add(clientId);

		Property clientSecret = new Property();
		clientSecret.setName(OIDCAuthenticatorConstants.CLIENT_SECRET);
		clientSecret.setDisplayName("Client Secret");
		clientSecret.setRequired(true);
		clientSecret.setConfidential(true);
		clientSecret.setDescription("Enter Foursquare client secret value");
		clientSecret.setDisplayOrder(1);
		configProperties.add(clientSecret);

		Property callbackUrl = new Property();
		callbackUrl.setDisplayName("Callback URL");
		callbackUrl.setName(IdentityApplicationConstants.OAuth2.CALLBACK_URL);
		callbackUrl.setDescription("Enter the callback URL");
		callbackUrl.setDisplayOrder(2);
		configProperties.add(callbackUrl);

		Property profileVersion = new Property();
		profileVersion.setDisplayName("Profile Version");
		profileVersion.setName(FoursquareAuthenticatorConstants.PROFILE_VERSION);
		profileVersion.setDescription("Enter the profile version");
		profileVersion.setDisplayOrder(3);
		configProperties.add(profileVersion);

		return configProperties;
	}

	/**
	 * This method are overridden for extra claim request to Foursquare end-point.
	 *
	 * @param request  the http request
	 * @param response the http response
	 * @param context  the authentication context
	 * @throws AuthenticationFailedException
	 */
	@Override
	protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
	                                             AuthenticationContext context) throws AuthenticationFailedException {
		try {
			Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
			String clientId = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID);
			String clientSecret = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_SECRET);
			String tokenEndPoint = FoursquareAuthenticatorConstants.FOURSQUARE_TOKEN_ENDPOINT;
			String callbackurl = getCallbackUrl(authenticatorProperties);
			OAuthAuthzResponse authzResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
			String code = authzResponse.getCode();
			try {
				OAuthClientRequest accessRequest =
						OAuthClientRequest.tokenLocation(tokenEndPoint).setGrantType(GrantType.AUTHORIZATION_CODE)
						                  .setClientId(clientId).setClientSecret(clientSecret)
						                  .setRedirectURI(callbackurl).setCode(code).buildBodyMessage();
				// create OAuth client that uses custom http client under the hood
				OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
				OAuthClientResponse oAuthResponse = oAuthClient.accessToken(accessRequest);
				String accessToken = oAuthResponse.getParam(FoursquareAuthenticatorConstants.ACCESS_TOKEN);
				if (StringUtils.isNotEmpty(accessToken)) {
					Map<ClaimMapping, String> claims = buildClaims(oAuthResponse, authenticatorProperties);
					if (claims != null && !claims.isEmpty()) {
						//Find the subject from the IDP claim mapping, subject Claim URI.
						String subjectFromClaims = FrameworkUtils
								.getFederatedSubjectFromClaims(context.getExternalIdP().getIdentityProvider(), claims);
						associateSubjectFromClaims(context, subjectFromClaims, claims);
					} else {
						if (log.isDebugEnabled()) {
							log.debug("Retrieving empty claims for the user");
						}
						throw new AuthenticationFailedException(
								"Claims for the user not found for access Token : " + accessToken);
					}
				} else {
					if (log.isDebugEnabled()) {
						log.debug("Retrieving invalid access token");
					}
					throw new AuthenticationFailedException("Could not receive a valid access token from Foursquare");
				}
			} catch (OAuthSystemException e) {
				throw new AuthenticationFailedException("Exception while building access token request ", e);
			} catch (ApplicationAuthenticatorException e) {
				throw new AuthenticationFailedException("Exception while building the claim mapping ", e);
			}
		} catch (OAuthProblemException e) {
			throw new AuthenticationFailedException("Exception while getting the access token form the response ", e);
		}
	}

	/**
	 * This method is to get the Foursquare user details.
	 *
	 * @param url         user info endpoint.
	 * @param accessToken access token.
	 * @return user info
	 * @throws ApplicationAuthenticatorException
	 */
	private JSONObject getUserInfo(String url, String accessToken) throws ApplicationAuthenticatorException {
		if (log.isDebugEnabled()) {
			log.debug("Sending the request for getting the user info");
		}
		StringBuilder jsonResponseCollector = new StringBuilder();
		BufferedReader bufferedReader = null;
		HttpURLConnection httpConnection = null;
		JSONObject jsonObj = null;
		try {
			URL obj = new URL(url + "&" + FoursquareAuthenticatorConstants.FOURSQUARE_OAUTH2_ACCESS_TOKEN_PARAMETER +
			                  "=" + accessToken);
			URLConnection connection = obj.openConnection();
			// Cast to a HttpURLConnection
			if (connection instanceof HttpURLConnection) {
				httpConnection = (HttpURLConnection) connection;
				httpConnection.setConnectTimeout(FoursquareAuthenticatorConstants.CONNECTION_TIMEOUT_VALUE);
				httpConnection.setReadTimeout(FoursquareAuthenticatorConstants.READ_TIMEOUT_VALUE);
				httpConnection.setRequestMethod(FoursquareAuthenticatorConstants.HTTP_GET_METHOD);
				bufferedReader = new BufferedReader(new InputStreamReader(httpConnection.getInputStream()));
			} else {
				if (log.isDebugEnabled()) {
					log.debug("Couldn't cast the HttpURLConnection");
				}
				throw new ApplicationAuthenticatorException(
						"Exception while casting the HttpURLConnection for " + connection.getURL());
			}
			String inputLine = bufferedReader.readLine();
			while (inputLine != null) {
				jsonResponseCollector.append(inputLine).append("\n");
				inputLine = bufferedReader.readLine();
			}
			jsonObj = new JSONObject(jsonResponseCollector.toString());
		} catch (MalformedURLException e) {
			throw new ApplicationAuthenticatorException(
					"MalformedURLException while generating the user info URL: " + url, e);
		} catch (ProtocolException e) {
			throw new ApplicationAuthenticatorException("ProtocolException while setting the request method: " +
			                                            FoursquareAuthenticatorConstants.HTTP_GET_METHOD +
			                                            " for the URL: " + url, e);
		} catch (IOException e) {
			throw new ApplicationAuthenticatorException("Error when reading the response from " + url +
			                                            "to update user claims ", e);
		} finally {
			IdentityIOStreamUtils.closeReader(bufferedReader);
			if (httpConnection != null) {
				httpConnection.disconnect();
			}
		}
		if (log.isDebugEnabled()) {
			log.debug("Receiving the response for the User info: " + jsonResponseCollector.toString());
		}
		return jsonObj;
	}

	/**
	 * Get the Foursquare specific claim dialect URI.
	 *
	 * @return Claim dialect URI.
	 */
	@Override
	public String getClaimDialectURI() {
		return FoursquareAuthenticatorConstants.CLAIM_DIALECT_URI;
	}

	/**
	 * This method is to build the claims for the user info.
	 *
	 * @param token                   token
	 * @param authenticatorProperties authenticatorProperties
	 * @return claims
	 */
	private Map<ClaimMapping, String> buildClaims(OAuthClientResponse token,
	                                              Map<String, String> authenticatorProperties)
			throws ApplicationAuthenticatorException {
		Map<ClaimMapping, String> claims = new HashMap<>();
		String accessToken = token.getParam("access_token");
		String url = FoursquareAuthenticatorConstants.FOURSQUARE_USER_INFO_ENDPOINT +
		             authenticatorProperties.get(FoursquareAuthenticatorConstants.PROFILE_VERSION);
		String claimUri;
		try {
			JSONObject userData = getUserInfo(url, accessToken);
			if (userData.length() == 0) {
				log.warn("Unable to fetch user claims. Proceeding without user claims");
				return claims;
			}
			JSONObject userObj = userData.getJSONObject(FoursquareAuthenticatorConstants.RESPONSE)
			                             .getJSONObject(FoursquareAuthenticatorConstants.USER);
			if (log.isDebugEnabled()) {
				log.debug("Getting the user's specific information and generating the specific claim dialect in to map");
			}
			if (userObj.has(FoursquareAuthenticatorConstants.ID) &&
			    StringUtils.isNotEmpty(userObj.get(FoursquareAuthenticatorConstants.ID).toString())) {
				claimUri =
						FoursquareAuthenticatorConstants.CLAIM_DIALECT_URI + "/" + FoursquareAuthenticatorConstants.ID;
				generateClaims(claimUri,claims,userObj.get(FoursquareAuthenticatorConstants.ID).toString());
			}
			if (userObj.has(FoursquareAuthenticatorConstants.FIRST_NAME) &&
			    StringUtils.isNotEmpty(userObj.get(FoursquareAuthenticatorConstants.FIRST_NAME).toString())) {
				claimUri = FoursquareAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
				           FoursquareAuthenticatorConstants.FIRST_NAME;
				generateClaims(claimUri,claims,userObj.get(FoursquareAuthenticatorConstants.FIRST_NAME).toString());
			}
			if (userObj.has(FoursquareAuthenticatorConstants.GENDER) &&
			    StringUtils.isNotEmpty(userObj.get(FoursquareAuthenticatorConstants.GENDER).toString())) {
				claimUri = FoursquareAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
				           FoursquareAuthenticatorConstants.GENDER;
				generateClaims(claimUri,claims,userObj.get(FoursquareAuthenticatorConstants.GENDER).toString());
			}
			if (userObj.has(FoursquareAuthenticatorConstants.LAST_NAME) &&
			    StringUtils.isNotEmpty(userObj.get(FoursquareAuthenticatorConstants.LAST_NAME).toString())) {
				claimUri = FoursquareAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
				           FoursquareAuthenticatorConstants.LAST_NAME;
				generateClaims(claimUri,claims,userObj.get(FoursquareAuthenticatorConstants.LAST_NAME).toString());
			}
			if (userObj.getJSONObject(FoursquareAuthenticatorConstants.CONTACT)
			           .has(FoursquareAuthenticatorConstants.EMAIL) && StringUtils.isNotEmpty(
					userObj.getJSONObject(FoursquareAuthenticatorConstants.CONTACT)
					       .get(FoursquareAuthenticatorConstants.EMAIL).toString())) {
				claimUri = FoursquareAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
				           FoursquareAuthenticatorConstants.EMAIL;
				generateClaims(claimUri,claims, userObj.getJSONObject(FoursquareAuthenticatorConstants.CONTACT)
				                                  .get(FoursquareAuthenticatorConstants.EMAIL).toString());
			}
			if (userObj.has(FoursquareAuthenticatorConstants.RELATIONSHIP) &&
			    StringUtils.isNotEmpty(userObj.get(FoursquareAuthenticatorConstants.RELATIONSHIP).toString())) {
				claimUri = FoursquareAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
				           FoursquareAuthenticatorConstants.RELATIONSHIP;
				generateClaims(claimUri,claims,userObj.get(FoursquareAuthenticatorConstants.RELATIONSHIP).toString());
			}
			if (userObj.has(FoursquareAuthenticatorConstants.CANONICAL_URL)) {
				claimUri = FoursquareAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
				           FoursquareAuthenticatorConstants.CANONICAL_URL;
				generateClaims(claimUri,claims,userObj.get(FoursquareAuthenticatorConstants.CANONICAL_URL).toString());
			}
			if (userObj.has(FoursquareAuthenticatorConstants.HOME_CITY) &&
			    StringUtils.isNotEmpty(userObj.get(FoursquareAuthenticatorConstants.HOME_CITY).toString())) {
				claimUri = FoursquareAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
				           FoursquareAuthenticatorConstants.HOME_CITY;
				generateClaims(claimUri,claims,userObj.get(FoursquareAuthenticatorConstants.HOME_CITY).toString());
			}
			if (userObj.has(FoursquareAuthenticatorConstants.BIO) &&
			    StringUtils.isNotEmpty(userObj.get(FoursquareAuthenticatorConstants.BIO).toString())) {
				claimUri = FoursquareAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
				           FoursquareAuthenticatorConstants.BIO;
				generateClaims(claimUri,claims,userObj.get(FoursquareAuthenticatorConstants.BIO).toString());
			}
		} catch (ApplicationAuthenticatorException e) {
			throw new ApplicationAuthenticatorException("Exception while fetching the user info from " + url, e);
		}
		return claims;
	}

	/**
	 * This method is to associate the specified value with the specified key in MAP
	 *
	 * @param claimUri The Claim URI
	 * @param claims The map
	 * @param value The value needs to be added in the MAP
	 */
	private void generateClaims(String claimUri,Map<ClaimMapping, String> claims,String value){
		if (log.isDebugEnabled()) {
			log.debug("Adding claim mapping");
		}
		ClaimMapping claimMapping = new ClaimMapping();
		Claim claim = new Claim();
		claim.setClaimUri(claimUri);
		claimMapping.setRemoteClaim(claim);
		claimMapping.setLocalClaim(claim);
		claims.put(claimMapping, value);
	}

	/**
	 * This method is to configure the subject identifier from the claims.
	 *
	 * @param context           AuthenticationContext
	 * @param subjectFromClaims subject identifier claim
	 * @param claims            claims
	 */
	private void associateSubjectFromClaims(AuthenticationContext context, String subjectFromClaims,
	                                        Map<ClaimMapping, String> claims) {
		//Use default claim URI on the Authenticator if claim mapping is not defined by the admin
		if (StringUtils.isBlank(subjectFromClaims)) {
			if (log.isDebugEnabled()) {
				log.debug("Setting userId as the default subject identifier");
			}
			String userId =
					FoursquareAuthenticatorConstants.CLAIM_DIALECT_URI + "/" + FoursquareAuthenticatorConstants.ID;
			ClaimMapping claimMapping = new ClaimMapping();
			Claim claim = new Claim();
			claim.setClaimUri(userId);
			claimMapping.setRemoteClaim(claim);
			claimMapping.setLocalClaim(claim);
			subjectFromClaims = claims.get(claimMapping);
		}
		AuthenticatedUser authenticatedUserObj =
				AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(subjectFromClaims);
		context.setSubject(authenticatedUserObj);
		authenticatedUserObj.setUserAttributes(claims);
	}
}