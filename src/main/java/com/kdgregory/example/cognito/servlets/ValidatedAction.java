// Copyright (c) Keith D Gregory, all rights reserved
package com.kdgregory.example.cognito.servlets;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.amazonaws.services.cognitoidp.model.*;
import net.sf.kdgcommons.lang.StringUtil;
import net.sf.kdgcommons.lang.ThreadUtil;


/**
 *  This servlet takes the place of some action that requires a valid user. It simply
 *  returns text indicating whether or not the user is authenticated.
 *  <p>
 *  In a real application, this validation logic (and associated cache) should be pushed
 *  into the abstract servlet.
 */
public class ValidatedAction extends AbstractCognitoServlet
{
    private static final long serialVersionUID = 1L;



    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
    throws ServletException, IOException
    {
        String accessToken = null;
        String refreshToken = null;

        logger.debug("attempting validation");

        Cookie[] cookies = request.getCookies();
        if (cookies == null)
        {
            logger.warn("request from {} did not have cookies", request.getRemoteAddr());
            reportResult(response, Constants.ResponseMessages.NOT_LOGGED_IN);
            return;
        }

        for (Cookie cookie : cookies)
        {
            if (cookie.getName().equals(Constants.CookieNames.ACCESS_TOKEN))
                accessToken = cookie.getValue();
            if (cookie.getName().equals(Constants.CookieNames.REFRESH_TOKEN))
                refreshToken = cookie.getValue();
        }

//        if (tokenCache.checkToken(accessToken))
//        {
//            logger.debug("token was found in cache, not going to AWS");
//            reportResult(response, Constants.ResponseMessages.LOGGED_IN);
//            return;
//        }

        try
        {
            GetUserRequest authRequest = new GetUserRequest().withAccessToken(accessToken);
            GetUserResult authResponse = cognitoClient.getUser(authRequest);

            logger.debug("successful validation for {}", authResponse.getUsername());
            tokenCache.addToken(accessToken);

            logger.debug(" - User attributes:");
            List<AttributeType> attrs = authResponse.getUserAttributes();
            for (AttributeType aType : attrs) {
                logger.debug("   -> {}: {}", aType.getName(), aType.getValue());
            }

            AdminListGroupsForUserRequest listGroups = new AdminListGroupsForUserRequest();
            listGroups.setUsername(authResponse.getUsername());
            listGroups.setLimit(50);
            listGroups.setUserPoolId(cognitoPoolId());
            AdminListGroupsForUserResult result = cognitoClient.adminListGroupsForUser(listGroups);

            logger.debug(" - Groups:");
            List<GroupType> groups = result.getGroups();
            for (GroupType gt : groups) {
                logger.debug("   -> {}", gt.getGroupName());
            }

            reportResult(response, Constants.ResponseMessages.LOGGED_IN);
        }
        catch (NotAuthorizedException ex)
        {
            if (ex.getErrorMessage().equals("Access Token has expired"))
            {
                attemptRefresh(refreshToken, response);
            }
            else
            {
                logger.warn("exception during validation: {}", ex.getMessage());
                reportResult(response, Constants.ResponseMessages.NOT_LOGGED_IN);
            }
        }
        catch (TooManyRequestsException ex)
        {
            logger.warn("caught TooManyRequestsException, delaying then retrying");
            ThreadUtil.sleepQuietly(250);
            doPost(request, response);
        }
    }


    /**
     *  Attempts to create a new access token based on the provided refresh token.
     */
    private void attemptRefresh(String refreshToken, HttpServletResponse response)
    throws ServletException, IOException
    {
        try
        {
            Map<String,String> authParams = new HashMap<String,String>();
            authParams.put("REFRESH_TOKEN", refreshToken);

            AdminInitiateAuthRequest refreshRequest = new AdminInitiateAuthRequest()
                                              .withAuthFlow(AuthFlowType.REFRESH_TOKEN)
                                              .withAuthParameters(authParams)
                                              .withClientId(cognitoClientId())
                                              .withUserPoolId(cognitoPoolId());

            AdminInitiateAuthResult refreshResponse = cognitoClient.adminInitiateAuth(refreshRequest);
            if (StringUtil.isBlank(refreshResponse.getChallengeName()))
            {
                logger.debug("successfully refreshed token");
                updateCredentialCookies(response, refreshResponse.getAuthenticationResult());
                reportResult(response, Constants.ResponseMessages.LOGGED_IN);
            }
            else
            {
                logger.warn("unexpected challenge when refreshing token: {}", refreshResponse.getChallengeName());
                reportResult(response, Constants.ResponseMessages.NOT_LOGGED_IN);
            }
        }
        catch (TooManyRequestsException ex)
        {
            logger.warn("caught TooManyRequestsException, delaying then retrying");
            ThreadUtil.sleepQuietly(250);
            attemptRefresh(refreshToken, response);
        }
        catch (AWSCognitoIdentityProviderException ex)
        {
            logger.debug("exception during token refresh: {}", ex.getMessage());
            reportResult(response, Constants.ResponseMessages.NOT_LOGGED_IN);
        }
    }


    @Override
    public String getServletInfo()
    {
        return "Checks authorization based on tokens stored in cookies";
    }

}
