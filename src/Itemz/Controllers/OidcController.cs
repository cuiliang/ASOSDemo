using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using System.Threading;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNetCore.Http.Authentication;
using Itemz.infrastructure.Oidc;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace Itemz.Controllers
{
    /// <summary>
    /// 处理OIDC连接
    /// </summary>
    public class OidcController : Controller
    {
        private OidcClientManager _clientManager = null;

        public OidcController(OidcClientManager clientManager)
        {            
            _clientManager = clientManager;
        }

        /// <summary>
        /// 
        /// 客户端请求 -》 Authorize -》 Login -》 Authroize -》 客户端
        /// </summary>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        [Route(OpenIdConnectServerDefaults.AuthorizationEndpointPath)]
        public async Task<IActionResult> Authorize(CancellationToken cancellationToken)
        {
            // Note: when a fatal error occurs during the request processing, an OpenID Connect response
            // is prematurely forged and added to the ASP.NET context by OpenIdConnectServerHandler.
            // You can safely remove this part and let ASOS automatically handle the unrecoverable errors
            // by switching ApplicationCanDisplayErrors to false in Startup.cs.
            var response = HttpContext.GetOpenIdConnectResponse();
            if (response != null)
            {
                return View("Error", response);
            }

            // Extract the authorization request from the ASP.NET environment.
            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null)
            {
                return View("Error", new OpenIdConnectMessage
                {
                    Error = OpenIdConnectConstants.Errors.ServerError,
                    ErrorDescription = "An internal error has occurred"
                });
            }

            // Note: authentication could be theorically enforced at the filter level via AuthorizeAttribute
            // but this authorization endpoint accepts both GET and POST requests while the cookie middleware
            // only uses 302 responses to redirect the user agent to the login page, making it incompatible with POST.
            // To work around this limitation, the OpenID Connect request is automatically saved in the cache and will be
            // restored by the OpenID Connect server middleware after the external authentication process has been completed.
            if (!User.Identities.Any(theIdentity => theIdentity.IsAuthenticated))
            {
                return Challenge(new AuthenticationProperties
                {
                    RedirectUri = Url.Action(nameof(Authorize), new
                    {
                        request_id = request.GetRequestId()
                    })
                });
            }

            // Note: ASOS automatically ensures that an application corresponds to the client_id specified
            // in the authorization request by calling IOpenIdConnectServerProvider.ValidateAuthorizationRequest.
            // In theory, this null check shouldn't be needed, but a race condition could occur if you
            // manually removed the application details from the database after the initial check made by ASOS.
            var application = _clientManager.FindByClientId(request.ClientId);
            if (application == null)
            {
                return View("Error", new OpenIdConnectMessage
                {
                    Error = OpenIdConnectConstants.Errors.InvalidClient,
                    ErrorDescription = "Details concerning the calling client application cannot be found in the database"
                });
            }

            // 注意：按正常的Oidc，此处应进入授权/Consent 页面请用户确认授权，不过因为本应用里只是做账户认证，不需要用户再手工确认了
            // 所以下面是直接返回确认的处理
            
            // Create a new ClaimsIdentity containing the claims that
            // will be used to create an id_token, a token or a code.
            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);

            // Copy the claims retrieved from the external identity provider
            // (e.g Google, Facebook, a WS-Fed provider or another OIDC server).
            foreach (var claim in HttpContext.User.Claims)
            {
                // Allow ClaimTypes.Name to be added in the id_token.
                // ClaimTypes.NameIdentifier is automatically added, even if its
                // destination is not defined or doesn't include "id_token".
                // The other claims won't be visible for the client application.
                if (claim.Type == ClaimTypes.Name)
                {
                    claim.SetDestinations(OpenIdConnectConstants.Destinations.AccessToken,
                                          OpenIdConnectConstants.Destinations.IdentityToken);
                }

                identity.AddClaim(claim);
            }

           
            // Create a new ClaimsIdentity containing the claims associated with the application.
            // Note: setting identity.Actor is not mandatory but can be useful to access
            // the whole delegation chain from the resource server (see ResourceController.cs).
            identity.Actor = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.Actor.AddClaim(ClaimTypes.NameIdentifier, application.ClientId);

            identity.Actor.AddClaim(ClaimTypes.Name, application.DisplayName,
                OpenIdConnectConstants.Destinations.AccessToken,
                OpenIdConnectConstants.Destinations.IdentityToken);

            // Create a new authentication ticket holding the user identity.
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            // Set the list of scopes granted to the client application.
            // Note: this sample always grants the "openid", "email" and "profile" scopes
            // when they are requested by the client application: a real world application
            // would probably display a form allowing to select the scopes to grant.
            ticket.SetScopes(new[] {
                /* openid: */ OpenIdConnectConstants.Scopes.OpenId,
                /* email: */ OpenIdConnectConstants.Scopes.Email,
                /* profile: */ OpenIdConnectConstants.Scopes.Profile,
                /* offline_access: */ OpenIdConnectConstants.Scopes.OfflineAccess
            }.Intersect(request.GetScopes()));

            // Set the resources servers the access token should be issued for.
            ticket.SetResources("resource_server");

            // Returning a SignInResult will ask ASOS to serialize the specified identity to build appropriate tokens.
            // Note: you should always make sure the identities you return contain ClaimTypes.NameIdentifier claim.
            // In this sample, the identity always contains the name identifier returned by the external provider.
            return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);


        }
    }
}