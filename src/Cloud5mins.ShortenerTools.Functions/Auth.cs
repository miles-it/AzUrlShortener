using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using Microsoft.Azure.Functions.Worker.Http;

namespace Cloud5mins.ShortenerTools
{
    public static class StaticWebAppsAuth
    {
        public class ClientPrincipal
        {
            public string IdentityProvider { get; set; }
            public string UserId { get; set; }
            public string UserDetails { get; set; }
            public IEnumerable<string> UserRoles { get; set; }
        }

        public static ClientPrincipal Parse(HttpRequestData req)
        {
            var principal = new ClientPrincipal();

            if (req.Headers.TryGetValues("X-MS-CLIENT-PRINCIPAL", out var head))
            {
                var data = head.First();
                var decoded = Convert.FromBase64String(data);
                var json = Encoding.UTF8.GetString(decoded);
                principal = JsonSerializer.Deserialize<ClientPrincipal>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }

            principal.UserRoles = principal.UserRoles?.Except(new string[] { "anonymous" }, StringComparer.CurrentCultureIgnoreCase);

            return principal;
        }

        public static bool IsAdmin(HttpRequestData req)
        {
            var principal = Parse(req);
            if (principal.UserRoles == null)
            {
                return false;
            }
            return principal.UserRoles.Contains("admin");
        }
    }
}