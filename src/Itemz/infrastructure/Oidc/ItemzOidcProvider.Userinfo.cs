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
using System.Security.Claims;
using System.Threading.Tasks;

namespace Itemz.infrastructure.Oidc
{
    public partial class ItemzOidcProvider : OpenIdConnectServerProvider
    {


        public override Task HandleUserinfoRequest(HandleUserinfoRequestContext context)
        {
            // Note: by default, OpenIdConnectServerHandler automatically handles userinfo requests and directly
            // writes the JSON response to the response stream. This sample uses a custom ProfileController that
            // handles userinfo requests: context.SkipToNextMiddleware() is called to bypass the default
            // request processing executed by OpenIdConnectServerHandler.
            context.SkipToNextMiddleware();

            return Task.FromResult<object>(null);
        }
   

            //public override async Task HandleUserinfoRequest([NotNull] HandleUserinfoRequestContext context)
            //{
            //    var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication>>();

            //    var principal = context.Ticket?.Principal;
            //    Debug.Assert(principal != null);

            //    // Note: user may be null if the user has been removed.
            //    // In this case, return a 400 response.
            //    var user = await services.Users.GetUserAsync(principal);
            //    if (user == null)
            //    {
            //        context.Response.StatusCode = 400;
            //        context.HandleResponse();

            //        return;
            //    }

            //    // Note: "sub" is a mandatory claim.
            //    // See http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
            //    context.Subject = await services.Users.GetUserIdAsync(user);

            //    // Only add the "preferred_username" claim if the "profile" scope was present in the access token.
            //    // Note: filtering the username is not needed at this stage as OpenIddictController.Accept
            //    // and OpenIddictProvider.GrantResourceOwnerCredentials are expected to reject requests that
            //    // don't include the "email" scope if the username corresponds to the registed email address.
            //    if (context.Ticket.HasScope(OpenIdConnectConstants.Scopes.Profile))
            //    {
            //        context.PreferredUsername = await services.Users.GetUserNameAsync(user);

            //        if (services.Users.SupportsUserClaim)
            //        {
            //            context.FamilyName = await services.Users.FindClaimAsync(user, ClaimTypes.Surname);
            //            context.GivenName = await services.Users.FindClaimAsync(user, ClaimTypes.GivenName);
            //            context.BirthDate = await services.Users.FindClaimAsync(user, ClaimTypes.DateOfBirth);
            //        }
            //    }

            //    // Only add the email address details if the "email" scope was present in the access token.
            //    if (services.Users.SupportsUserEmail && context.Ticket.HasScope(OpenIdConnectConstants.Scopes.Email))
            //    {
            //        context.Email = await services.Users.GetEmailAsync(user);

            //        // Only add the "email_verified" claim
            //        // if the email address is non-null.
            //        if (!string.IsNullOrEmpty(context.Email))
            //        {
            //            context.EmailVerified = await services.Users.IsEmailConfirmedAsync(user);
            //        }
            //    };

            //    // Only add the phone number details if the "phone" scope was present in the access token.
            //    if (services.Users.SupportsUserPhoneNumber &&
            //        context.Ticket.HasScope(OpenIdConnectConstants.Scopes.Phone))
            //    {
            //        context.PhoneNumber = await services.Users.GetPhoneNumberAsync(user);

            //        // Only add the "phone_number_verified"
            //        // claim if the phone number is non-null.
            //        if (!string.IsNullOrEmpty(context.PhoneNumber))
            //        {
            //            context.PhoneNumberVerified = await services.Users.IsPhoneNumberConfirmedAsync(user);
            //        }
            //    }

            //    // Only add the roles list if the "roles" scope was present in the access token.
            //    if (services.Users.SupportsUserRole && context.Ticket.HasScope(OpenIddictConstants.Scopes.Roles))
            //    {
            //        var roles = await services.Users.GetRolesAsync(user);
            //        if (roles.Count != 0)
            //        {
            //            context.Claims[OpenIddictConstants.Claims.Roles] = JArray.FromObject(roles);
            //        }
            //    }
            //}
        }
}
