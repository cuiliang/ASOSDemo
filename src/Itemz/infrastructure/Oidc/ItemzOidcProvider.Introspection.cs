using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Server;
using Itemz.Models;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace Itemz.infrastructure.Oidc
{
    public partial class ItemzOidcProvider : OpenIdConnectServerProvider
    {
        public override async Task ValidateIntrospectionRequest([NotNull] ValidateIntrospectionRequestContext context)
        {
            //var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication>>();
            var clientMgr = context.HttpContext.RequestServices.GetRequiredService<OidcClientManager>();


            // Note: ASOS supports both GET and POST introspection requests but OpenIddict only accepts POST requests.
            if (!string.Equals(context.HttpContext.Request.Method, "POST", StringComparison.OrdinalIgnoreCase))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "Introspection requests must use HTTP POST.");

                return;
            }

            // Note: ASOS supports unauthenticated introspection requests but OpenIddict uses
            // a stricter policy preventing unauthenticated/public applications from using
            // the introspection endpoint, as required by the specifications.
            // See https://tools.ietf.org/html/rfc7662 for more information.
            if (string.IsNullOrEmpty(context.ClientId) || string.IsNullOrEmpty(context.ClientSecret))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "Clients must be authenticated to use the introspection endpoint.");

                return;
            }

            // Retrieve the application details corresponding to the requested client_id.
            var application = clientMgr.FindByClientId(context.ClientId);
            if (application == null)
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Application not found in the database: ensure that your client_id is correct.");

                return;
            }

            //// Reject non-confidential applications.
            //if (await services.Applications.IsPublicApplicationAsync(application))
            //{
            //    context.Reject(
            //        error: OpenIdConnectConstants.Errors.InvalidClient,
            //        description: "Public applications are not allowed to use the introspection endpoint.");

            //    return;
            //}

            // Validate the client credentials.
            if (! String.Equals(application.Secret, context.ClientSecret))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Invalid credentials: ensure that you specified a correct client_secret.");

                return;
            }

            context.Validate();
        }

        public override async Task HandleIntrospectionRequest([NotNull] HandleIntrospectionRequestContext context)
        {
            //var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication>>();
            var options = context.HttpContext.RequestServices.GetRequiredService<IOptions<IdentityOptions>>();
            var userManager = context.HttpContext.RequestServices.GetService<UserManager<ApplicationUser>>();

            // If the user manager doesn't support security
            // stamps, skip the additional validation logic.
            if (!userManager.SupportsUserSecurityStamp)
            {
                return;
            }

            var principal = context.Ticket?.Principal;
            Debug.Assert(principal != null);

            var user = await userManager.GetUserAsync(principal);
            if (user == null)
            {
                context.Active = false;

                return;
            }

            var identifier = principal.GetClaim(options.Value.ClaimsIdentity.SecurityStampClaimType);
            if (!string.IsNullOrEmpty(identifier) &&
                !string.Equals(identifier, await userManager.GetSecurityStampAsync(user), StringComparison.Ordinal))
            {
                context.Active = false;

                return;
            }
        }
    }
}
