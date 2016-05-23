using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Itemz.infrastructure.Oidc
{
    /// <summary>
    /// Oidc 客户端管理器
    /// </summary>
    public class OidcClientManager
    {
        private IList<OidcClient> _clients = new List<OidcClient>();

        public void AddClient(OidcClient client)
        {
            _clients.Add(client);
        }

        public OidcClient Find(Func<OidcClient, bool> predicate)
        {
            return _clients.FirstOrDefault(predicate);
        }

        /// <summary>
        /// 根据ClientId获取Client
        /// </summary>
        /// <param name="clientId"></param>
        /// <returns></returns>
        public OidcClient FindByClientId(string clientId)
        {
            return _clients.FirstOrDefault(c => String.Equals(c.ClientId, clientId, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// 判断某个LogoutRedirect是否合法
        /// </summary>
        /// <param name="uri"></param>
        /// <returns></returns>
        public bool IsValidPostLogoutRedirectUri(string uri)
        {
            return _clients.Any(c => String.Equals(c.LogoutRedirectUri, uri, StringComparison.OrdinalIgnoreCase));
        }

        public OidcClient FindApplicationByLogoutRedirectUri(string postLogoutRedirectUri)
        {
            return _clients.FirstOrDefault(c => String.Equals(c.LogoutRedirectUri, postLogoutRedirectUri));
        }
    }
}
