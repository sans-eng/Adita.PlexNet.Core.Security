using Adita.PlexNet.Core.Security.Claims;
using System.Security.Claims;

namespace Adita.PlexNet.Core.Security.Test.Claims
{
    [TestClass]
    public class ApplicationIdentityTest
    {
        [TestMethod]
        public void CanCreateDefaultApplicationIdentity()
        {
            ApplicationIdentity applicationIdentity = new();

            Assert.IsNull(applicationIdentity.AuthenticationType);
            Assert.IsFalse(applicationIdentity.IsAuthenticated);
            Assert.IsTrue(applicationIdentity.IsAnonymous);
            Assert.IsNull(applicationIdentity.Name);

            Assert.IsTrue(applicationIdentity.Claims.Count == 0);
            Assert.IsTrue(applicationIdentity.NameClaimType == ClaimTypes.Name);
            Assert.IsTrue(applicationIdentity.RoleClaimType == ClaimTypes.Role);
        }

        [TestMethod]
        public void CanCreateEmptyClaimsApplicationIdentity()
        {
            ApplicationIdentity applicationIdentity = new("password");

            Assert.IsTrue(applicationIdentity.AuthenticationType == "password");
            Assert.IsTrue(applicationIdentity.IsAuthenticated);
            Assert.IsTrue(applicationIdentity.IsAnonymous);
            Assert.IsNull(applicationIdentity.Name);

            Assert.IsTrue(applicationIdentity.Claims.Count == 0);
            Assert.IsTrue(applicationIdentity.NameClaimType == ClaimTypes.Name);
            Assert.IsTrue(applicationIdentity.RoleClaimType == ClaimTypes.Role);

            ApplicationIdentity applicationIdentity1 = new("password", ClaimTypes.Name, ClaimTypes.Role);

            Assert.IsTrue(applicationIdentity.AuthenticationType == "password");
            Assert.IsTrue(applicationIdentity1.IsAuthenticated);
            Assert.IsTrue(applicationIdentity1.IsAnonymous);
            Assert.IsNull(applicationIdentity1.Name);

            Assert.IsTrue(applicationIdentity1.Claims.Count == 0);
            Assert.IsTrue(applicationIdentity1.NameClaimType == ClaimTypes.Name);
            Assert.IsTrue(applicationIdentity1.RoleClaimType == ClaimTypes.Role);
        }

        [TestMethod]
        public void CanCreateWithClaimsApplicationIdentity()
        {
            ApplicationIdentity applicationIdentity = new(new List<Claim> { new Claim(ClaimTypes.Name, "Adi"), new Claim(ClaimTypes.Role, "admin") }, "password");

            Assert.IsTrue(applicationIdentity.AuthenticationType == "password");
            Assert.IsTrue(applicationIdentity.IsAuthenticated);
            Assert.IsFalse(applicationIdentity.IsAnonymous);
            Assert.IsNotNull(applicationIdentity.Name);

            Assert.IsTrue(applicationIdentity.Claims.Count > 0);
            Assert.IsTrue(applicationIdentity.NameClaimType == ClaimTypes.Name);
            Assert.IsTrue(applicationIdentity.RoleClaimType == ClaimTypes.Role);

            Assert.IsTrue(applicationIdentity.HasClaim(ClaimTypes.Name, "Adi"));
            Assert.IsTrue(applicationIdentity.HasClaim(ClaimTypes.Role, "admin"));

        }

        [TestMethod]
        public void CanAddClaims()
        {
            ApplicationIdentity applicationIdentity = new(new List<Claim> { new Claim(ClaimTypes.Name, "Adi"), new Claim(ClaimTypes.Role, "admin") }, "password");

            Assert.IsTrue(applicationIdentity.AuthenticationType == "password");
            Assert.IsTrue(applicationIdentity.IsAuthenticated);
            Assert.IsFalse(applicationIdentity.IsAnonymous);
            Assert.IsNotNull(applicationIdentity.Name);

            Assert.IsTrue(applicationIdentity.Claims.Count > 0);
            Assert.IsTrue(applicationIdentity.NameClaimType == ClaimTypes.Name);
            Assert.IsTrue(applicationIdentity.RoleClaimType == ClaimTypes.Role);

            Assert.IsTrue(applicationIdentity.HasClaim(ClaimTypes.Name, "Adi"));
            Assert.IsTrue(applicationIdentity.HasClaim(ClaimTypes.Role, "admin"));

            applicationIdentity.AddClaim(new Claim(ClaimTypes.MobilePhone, "088778"));
            Assert.IsTrue(applicationIdentity.HasClaim(ClaimTypes.MobilePhone, "088778"));

            List<Claim> claims = new List<Claim> { new Claim(ClaimTypes.HomePhone, "08888") };

            applicationIdentity.AddClaims(claims);
            Assert.IsTrue(applicationIdentity.HasClaim(o => o.Type == ClaimTypes.HomePhone && o.Value == "08888"));

            Assert.IsTrue(applicationIdentity.FindAll(o => o.Type == ClaimTypes.HomePhone && o.Value == "08888").Any());
        }

        [TestMethod]
        public void CanRemoveClaim()
        {
            ApplicationIdentity applicationIdentity = new(new List<Claim> { new Claim(ClaimTypes.Name, "Adi"), new Claim(ClaimTypes.Role, "admin") }, "password");

            Assert.IsTrue(applicationIdentity.AuthenticationType == "password");
            Assert.IsTrue(applicationIdentity.IsAuthenticated);
            Assert.IsFalse(applicationIdentity.IsAnonymous);
            Assert.IsNotNull(applicationIdentity.Name);

            Assert.IsTrue(applicationIdentity.Claims.Count > 0);
            Assert.IsTrue(applicationIdentity.NameClaimType == ClaimTypes.Name);
            Assert.IsTrue(applicationIdentity.RoleClaimType == ClaimTypes.Role);

            Assert.IsTrue(applicationIdentity.HasClaim(ClaimTypes.Name, "Adi"));
            Assert.IsTrue(applicationIdentity.HasClaim(ClaimTypes.Role, "admin"));

            Claim claim = new Claim(ClaimTypes.MobilePhone, "088778");

            applicationIdentity.AddClaim(claim);
            Assert.IsTrue(applicationIdentity.HasClaim(ClaimTypes.MobilePhone, "088778"));

            applicationIdentity.RemoveClaim(claim);
            Assert.IsFalse(applicationIdentity.HasClaim(ClaimTypes.MobilePhone, "088778"));
        }
    }
}
