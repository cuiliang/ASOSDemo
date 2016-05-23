using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Itemz.infrastructure.Oidc
{
    /// <summary>
    /// Oidc客户端定义
    /// </summary>
    public class OidcClient
    {
        public string ClientId { get; set; }
        public string DisplayName { get; set; }
        public string RedirectUri { get; set; }
        public string LogoutRedirectUri { get; set; }
        public string Secret { get; set; }
    }
}
