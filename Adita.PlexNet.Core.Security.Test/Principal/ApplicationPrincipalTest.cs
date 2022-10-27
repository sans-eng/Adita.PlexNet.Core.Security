using Adita.PlexNet.Core.Security.Claims;
using Adita.PlexNet.Core.Security.Principals;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Adita.PlexNet.Core.Security.Test.Principal
{
    [TestClass]
    public class ApplicationPrincipalTest
    {
        [TestMethod]
        public void CanCreateApplicationPrincipal()
        {
            ApplicationIdentity applicationIdentity = new(new List<Claim> { new Claim(ClaimTypes.Name, "Adi"), new Claim(ClaimTypes.Role, "admin") }, "password");

            ApplicationPrincipal applicationPrincipal = new(applicationIdentity);

            Assert.IsTrue(applicationPrincipal.IsInRole("admin"));
            Assert.IsTrue(applicationPrincipal.HasClaim(ClaimTypes.Name, "Adi"));
            Assert.IsTrue(applicationPrincipal.HasClaim(o => o.Type == ClaimTypes.Role && o.Value == "admin"));
        }

        [TestMethod]
        public void CanSetIdentity()
        {
            ApplicationIdentity applicationIdentity = new(new List<Claim> { new Claim(ClaimTypes.Name, "Adi"), new Claim(ClaimTypes.Role, "admin") }, "password");

            ApplicationPrincipal applicationPrincipal = new(applicationIdentity);

            Assert.IsTrue(applicationPrincipal.IsInRole("admin"));
            Assert.IsTrue(applicationPrincipal.HasClaim(ClaimTypes.Name, "Adi"));
            Assert.IsTrue(applicationPrincipal.HasClaim(o => o.Type == ClaimTypes.Role && o.Value == "admin"));

            ApplicationIdentity applicationIdentity2 = new(new List<Claim> { new Claim(ClaimTypes.Name, "Anita"), new Claim(ClaimTypes.Role, "admin") }, "password");
            applicationPrincipal.SetIdentity(applicationIdentity2);

            Assert.IsTrue(applicationPrincipal.IsInRole("admin"));
            Assert.IsTrue(applicationPrincipal.HasClaim(ClaimTypes.Name, "Anita"));
            Assert.IsTrue(applicationPrincipal.HasClaim(o => o.Type == ClaimTypes.Role && o.Value == "admin"));
        }
    }
}
