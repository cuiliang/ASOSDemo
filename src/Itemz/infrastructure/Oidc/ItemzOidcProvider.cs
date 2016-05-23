using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Itemz.Data;
using Microsoft.AspNetCore.Identity;
using Itemz.Models;
using System.Security.Claims;
using System.Diagnostics;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Http;

namespace Itemz.infrastructure.Oidc
{
    public partial class ItemzOidcProvider : OpenIdConnectServerProvider
    {


        public override Task MatchEndpoint(MatchEndpointContext context)
        {
            // Note: by default, OpenIdConnectServerHandler only handles authorization requests made to the authorization endpoint.
            // This context handler uses a more relaxed policy that allows extracting authorization requests received at
            // /connect/authorize/accept and /connect/authorize/deny (see AuthorizationController.cs for more information).
            if (context.Options.AuthorizationEndpointPath.HasValue &&
                context.Request.Path.StartsWithSegments(context.Options.AuthorizationEndpointPath))
            {
                context.MatchesAuthorizationEndpoint();
            }

            return Task.FromResult<object>(null);
        }

        public override async Task ValidateAuthorizationRequest(ValidateAuthorizationRequestContext context)
        {

            // Note: redirect_uri is not required for pure OAuth2 requests
            // but this provider uses a stricter policy making it mandatory,
            // as required by the OpenID Connect core specification.
            // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest.
            if (string.IsNullOrEmpty(context.RedirectUri))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "The required redirect_uri parameter was missing.");

                return;
            }

            var clientMgr = context.HttpContext.RequestServices.GetRequiredService<OidcClientManager>();

            // Retrieve the application details corresponding to the requested client_id.
            var application = clientMgr.FindByClientId(context.ClientId);
            if (application == null)
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Application not found in the database: ensure that your client_id is correct");

                return;
            }

            if (!string.IsNullOrEmpty(context.RedirectUri) &&
                !string.Equals(context.RedirectUri, application.RedirectUri, StringComparison.Ordinal))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Invalid redirect_uri");

                return;
            }

            // To prevent downgrade attacks, ensure that authorization requests using the hybrid/implicit
            // flow are rejected if the client identifier corresponds to a confidential application.
            // Note: when using the authorization code grant, ValidateClientAuthentication is responsible of
            // rejecting the token request if the client_id corresponds to an unauthenticated confidential client.
            //if (await services.Applications.IsConfidentialApplicationAsync(application) && !context.Request.IsAuthorizationCodeFlow())
            //{
            //    context.Reject(
            //        error: OpenIdConnectConstants.Errors.InvalidRequest,
            //        description: "Confidential clients can only use response_type=code.");
            //    return;
            //}

            // If the user is connected, ensure that a corresponding profile exists and that
            // the appropriate set of scopes is requested to prevent personal data leakage.
            if (context.HttpContext.User.Identities.Any(identity => identity.IsAuthenticated))
            {
                var userManager = context.HttpContext.RequestServices.GetService<UserManager<ApplicationUser>>();

                // Ensure the user profile still exists in the database.
                var user = await userManager.GetUserAsync(context.HttpContext.User);
                if (user == null)
                {
                    context.Reject(
                        error: OpenIdConnectConstants.Errors.ServerError,
                        description: "An internal error has occurred.");

                    return;
                }

                //// Return an error if the username corresponds to the registered
                //// email address and if the "email" scope has not been requested.
                //if (userManager.SupportsUserEmail && context.Request.HasScope(OpenIdConnectConstants.Scopes.Profile) &&
                //                                       !context.Request.HasScope(OpenIdConnectConstants.Scopes.Email))
                //{
                //    // Retrieve the username and the email address associated with the user.
                //    var username = await userManager.GetUserNameAsync(user);
                //    var email = await userManager.GetEmailAsync(user);

                //    if (!string.IsNullOrEmpty(email) && string.Equals(username, email, StringComparison.OrdinalIgnoreCase))
                //    {
                //        context.Reject(
                //            error: OpenIdConnectConstants.Errors.InvalidRequest,
                //            description: "The 'email' scope is required.");

                //        return;
                //    }
                //}
            }

            // Run additional checks for prompt=none requests.
            if (string.Equals(context.Request.Prompt, "none", StringComparison.Ordinal))
            {
                // If the user is not authenticated, return an error to the client application.
                // See http://openid.net/specs/openid-connect-core-1_0.html#Authenticates
                if (!context.HttpContext.User.Identities.Any(identity => identity.IsAuthenticated))
                {
                    context.Reject(
                        error: OpenIdConnectConstants.Errors.LoginRequired,
                        description: "The user must be authenticated.");

                    return;
                }

                // Ensure that the authentication cookie contains the required NameIdentifier claim.
                var identifier = context.HttpContext.User.GetClaim(ClaimTypes.NameIdentifier);
                if (string.IsNullOrEmpty(identifier))
                {
                    context.Reject(
                        error: OpenIdConnectConstants.Errors.ServerError,
                        description: "The authorization request cannot be processed.");

                    return;
                }

                // Extract the principal contained in the id_token_hint parameter.
                // If no principal can be extracted, an error is returned to the client application.
                var principal = await context.HttpContext.Authentication.AuthenticateAsync(context.Options.AuthenticationScheme);
                if (principal == null)
                {
                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "The required id_token_hint parameter is missing.");

                    return;
                }

                // Ensure the client application is listed as a valid audience in the identity token
                // and that the identity token corresponds to the authenticated user.
                if (!principal.HasClaim(OpenIdConnectConstants.Claims.Audience, context.Request.ClientId) ||
                    !principal.HasClaim(ClaimTypes.NameIdentifier, identifier))
                {
                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "The id_token_hint parameter is invalid.");

                    return;
                }
            }

            context.Validate(application.RedirectUri);
        }


        public override async Task HandleAuthorizationRequest([NotNull] HandleAuthorizationRequestContext context)
        {
            // Only handle prompt=none requests at this stage.
            if (!string.Equals(context.Request.Prompt, "none", StringComparison.Ordinal))
            {
                return;
            }

            //var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication>>();

            // Note: principal is guaranteed to be non-null since ValidateAuthorizationRequest
            // rejects prompt=none requests missing or having an invalid id_token_hint.
            var principal = await context.HttpContext.Authentication.AuthenticateAsync(context.Options.AuthenticationScheme);
            Debug.Assert(principal != null);

            var userManager = context.HttpContext.RequestServices.GetService<UserManager<ApplicationUser>>();

            // Note: user may be null if the user was removed after
            // the initial check made by ValidateAuthorizationRequest.
            // In this case, ignore the prompt=none request and
            // continue to the next middleware in the pipeline.
            var user = await userManager.GetUserAsync(principal);
            if (user == null)
            {
                return;
            }

            // Note: filtering the username is not needed at this stage as OpenIddictController.Accept
            // and OpenIddictProvider.GrantResourceOwnerCredentials are expected to reject requests that
            // don't include the "email" scope if the username corresponds to the registed email address.
            var identity = await CreateIdentityAsync(context.HttpContext, user, context.Request.GetScopes());
            Debug.Assert(identity != null);

            // Create a new authentication ticket holding the user identity.
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                context.Options.AuthenticationScheme);

            ticket.SetResources(context.Request.GetResources());
            ticket.SetScopes(context.Request.GetScopes());

            // Call SignInAsync to create and return a new OpenID Connect response containing the serialized code/tokens.
            await context.HttpContext.Authentication.SignInAsync(ticket.AuthenticationScheme, ticket.Principal, ticket.Properties);

            // Mark the response as handled
            // to skip the rest of the pipeline.
            context.HandleResponse();
        }

        private async Task<ClaimsIdentity> CreateIdentityAsync(HttpContext context, ApplicationUser user, IEnumerable<string> scopes)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (scopes == null)
            {
                throw new ArgumentNullException(nameof(scopes));
            }

            var Options = context.RequestServices.GetRequiredService<IOptions<IdentityOptions>>().Value;

            var identity = new ClaimsIdentity(
                OpenIdConnectServerDefaults.AuthenticationScheme,
                Options.ClaimsIdentity.UserNameClaimType,
                Options.ClaimsIdentity.RoleClaimType);

            var userManager = context.RequestServices.GetService<UserManager<ApplicationUser>>();

            // Note: the name identifier is always included in both identity and
            // access tokens, even if an explicit destination is not specified.
            identity.AddClaim(ClaimTypes.NameIdentifier, await userManager.GetUserIdAsync(user));

            // Resolve the email address associated with the user if the underlying store supports it.
            var email = userManager.SupportsUserEmail ? await userManager.GetEmailAsync(user) : null;

            // Only add the name claim if the "profile" scope was granted.
            if (scopes.Contains(OpenIdConnectConstants.Scopes.Profile))
            {
                var username = await userManager.GetUserNameAsync(user);

                // Throw an exception if the username corresponds to the registered
                // email address and if the "email" scope has not been requested.
                if (!scopes.Contains(OpenIdConnectConstants.Scopes.Email) &&
                    !string.IsNullOrEmpty(email) &&
                     string.Equals(username, email, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException("The 'email' scope is required.");
                }

                identity.AddClaim(ClaimTypes.Name, username,
                    OpenIdConnectConstants.Destinations.AccessToken,
                    OpenIdConnectConstants.Destinations.IdentityToken);
            }

            // Only add the email address if the "email" scope was granted.
            if (!string.IsNullOrEmpty(email) && scopes.Contains(OpenIdConnectConstants.Scopes.Email))
            {
                identity.AddClaim(ClaimTypes.Email, email,
                    OpenIdConnectConstants.Destinations.AccessToken,
                    OpenIdConnectConstants.Destinations.IdentityToken);
            }

            //if (userManager.SupportsUserRole && scopes.Contains(OpenIddictConstants.Scopes.Roles))
            //{
            //    foreach (var role in await Services.Users.GetRolesAsync(user))
            //    {
            //        identity.AddClaim(identity.RoleClaimType, role,
            //            OpenIdConnectConstants.Destinations.AccessToken,
            //            OpenIdConnectConstants.Destinations.IdentityToken);
            //    }
            //}

            if (userManager.SupportsUserSecurityStamp)
            {
                var identifier = await userManager.GetSecurityStampAsync(user);

                if (!string.IsNullOrEmpty(identifier))
                {
                    identity.AddClaim(Options.ClaimsIdentity.SecurityStampClaimType, identifier,
                        OpenIdConnectConstants.Destinations.AccessToken,
                        OpenIdConnectConstants.Destinations.IdentityToken);
                }
            }

            return identity;
        }


        public override async Task ValidateTokenRequest(ValidateTokenRequestContext context)
        {
            // Note: OpenIdConnectServerHandler supports authorization code, refresh token,
            // client credentials, resource owner password credentials and custom grants
            // but this authorization server uses a stricter policy rejecting custom grant types.
            if (!context.Request.IsAuthorizationCodeGrantType() && !context.Request.IsRefreshTokenGrantType() &&
                !context.Request.IsPasswordGrantType() && !context.Request.IsClientCredentialsGrantType())
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnsupportedGrantType,
                    description: "Only authorization code, refresh token, client credentials " +
                                 "and password grants are accepted by this authorization server.");

                return;
            }

            // Note: though required by the OpenID Connect specification for the refresh token grant,
            // client authentication is not mandatory for non-confidential client applications in OAuth2.
            // To avoid breaking OAuth2 scenarios, OpenIddict uses a relaxed policy that allows
            // public applications to use the refresh token grant without having to authenticate.
            // See http://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken
            // and https://tools.ietf.org/html/rfc6749#section-6 for more information.

            // Skip client authentication if the client identifier is missing.
            // Note: ASOS will automatically ensure that the calling application
            // cannot use an authorization code or a refresh token if it's not
            // the intended audience, even if client authentication was skipped.
            if (string.IsNullOrEmpty(context.ClientId))
            {
                context.Skip();

                return;
            }

            //var database = context.HttpContext.RequestServices.GetRequiredService<ApplicationDbContext>();
            var clientMgr = context.HttpContext.RequestServices.GetRequiredService<OidcClientManager>();

            // Retrieve the application details corresponding to the requested client_id.
            var application = clientMgr.FindByClientId(context.ClientId);

            if (application == null)
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Application not found in the database: ensure that your client_id is correct");

                return;
            }


            // Openiddict的做法不同，而是区分Public 和 Confidential,public的禁止传送client_secret
            if (!string.Equals(context.ClientSecret, application.Secret, StringComparison.Ordinal))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Invalid credentials: ensure that you specified a correct client_secret");

                return;
            }




            context.Validate();
        }


        public override async Task GrantClientCredentials([NotNull] GrantClientCredentialsContext context)
        {
            //var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication>>();

            var clientMgr = context.HttpContext.RequestServices.GetRequiredService<OidcClientManager>();
            // Retrieve the application details corresponding to the requested client_id.
            var application = clientMgr.FindByClientId(context.ClientId);
            Debug.Assert(application != null);

            var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);

            // Note: the name identifier is always included in both identity and
            // access tokens, even if an explicit destination is not specified.
            identity.AddClaim(ClaimTypes.NameIdentifier, context.ClientId);

            identity.AddClaim(ClaimTypes.Name, application.DisplayName,
                OpenIdConnectConstants.Destinations.AccessToken,
                OpenIdConnectConstants.Destinations.IdentityToken);

            // Create a new authentication ticket
            // holding the application identity.
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                context.Options.AuthenticationScheme);

            ticket.SetResources(context.Request.GetResources());
            ticket.SetScopes(context.Request.GetScopes());

            context.Validate(ticket);
        }

        public override async Task GrantRefreshToken([NotNull] GrantRefreshTokenContext context)
        {
            //var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication>>();
            var userManager = context.HttpContext.RequestServices.GetService<UserManager<ApplicationUser>>();
            var options = context.HttpContext.RequestServices.GetRequiredService<IOptions<IdentityOptions>>();

            var principal = context.Ticket?.Principal;
            Debug.Assert(principal != null);

            var user = await userManager.GetUserAsync(principal);
            if (user == null)
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "The refresh token is no longer valid.");

                return;
            }

            // If the user manager supports security stamps,
            // ensure that the refresh token is still valid.
            if (userManager.SupportsUserSecurityStamp)
            {
                var identifier = principal.GetClaim(options.Value.ClaimsIdentity.SecurityStampClaimType);
                if (!string.IsNullOrEmpty(identifier) &&
                    !string.Equals(identifier, await userManager.GetSecurityStampAsync(user), StringComparison.Ordinal))
                {
                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidGrant,
                        description: "The refresh token is no longer valid.");

                    return;
                }
            }

            // Note: the "scopes" property stored in context.AuthenticationTicket is automatically
            // updated by ASOS when the client application requests a restricted scopes collection.
            var identity = await CreateIdentityAsync(context.HttpContext, user, context.Ticket.GetScopes());
            Debug.Assert(identity != null);

            // Create a new authentication ticket holding the user identity but
            // reuse the authentication properties stored in the refresh token.
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                context.Ticket.Properties,
                context.Options.AuthenticationScheme);

            context.Validate(ticket);
        }

        public override async Task GrantResourceOwnerCredentials([NotNull] GrantResourceOwnerCredentialsContext context)
        {
            //var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication>>();
            var userManager = context.HttpContext.RequestServices.GetService<UserManager<ApplicationUser>>();
            var signinManager = context.HttpContext.RequestServices.GetService<SignInManager<ApplicationUser>>();

            var user = await userManager.FindByNameAsync(context.UserName);
            if (user == null)
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "Invalid credentials.");

                return;
            }

            // Ensure the user is allowed to sign in.
            if (!await signinManager.CanSignInAsync(user))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "The user is not allowed to sign in.");

                return;
            }

            // Ensure the user is not already locked out.
            if (userManager.SupportsUserLockout && await userManager.IsLockedOutAsync(user))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "Account locked out.");

                return;
            }

            // Ensure the password is valid.
            if (!await userManager.CheckPasswordAsync(user, context.Password))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "Invalid credentials.");

                if (userManager.SupportsUserLockout)
                {
                    await userManager.AccessFailedAsync(user);

                    // Ensure the user is not locked out.
                    if (await userManager.IsLockedOutAsync(user))
                    {
                        context.Reject(
                            error: OpenIdConnectConstants.Errors.InvalidGrant,
                            description: "Account locked out.");
                    }
                }

                return;
            }

            if (userManager.SupportsUserLockout)
            {
                await userManager.ResetAccessFailedCountAsync(user);
            }

            // Reject the token request if two-factor authentication has been enabled by the user.
            if (userManager.SupportsUserTwoFactor && await userManager.GetTwoFactorEnabledAsync(user))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "Two-factor authentication is required for this account.");

                return;
            }

            // Return an error if the username corresponds to the registered
            // email address and if the "email" scope has not been requested.
            if (userManager.SupportsUserEmail && context.Request.HasScope(OpenIdConnectConstants.Scopes.Profile) &&
                                                   !context.Request.HasScope(OpenIdConnectConstants.Scopes.Email))
            {
                // Retrieve the username and the email address associated with the user.
                var username = await userManager.GetUserNameAsync(user);
                var email = await userManager.GetEmailAsync(user);

                if (!string.IsNullOrEmpty(email) && string.Equals(username, email, StringComparison.OrdinalIgnoreCase))
                {
                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "The 'email' scope is required.");

                    return;
                }
            }

            var identity = await CreateIdentityAsync(context.HttpContext, user, context.Request.GetScopes());
            Debug.Assert(identity != null);

            // Create a new authentication ticket holding the user identity.
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                context.Options.AuthenticationScheme);

            ticket.SetResources(context.Request.GetResources());
            ticket.SetScopes(context.Request.GetScopes());

            context.Validate(ticket);
        }


    }

        

}
