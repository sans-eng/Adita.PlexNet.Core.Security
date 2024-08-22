using Adita.PlexNet.Core.Security.Authorization;
using Adita.PlexNet.Core.Security.Claims;
using Adita.PlexNet.Core.Security.Principals;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Claims;

namespace Adita.PlexNet.Core.Security.Test.Authorization
{
    [TestClass]
    public class AuthorizaztionManagerTest
    {
        [Authorize("admin")]
        public int Resource1 { get; }
        [Authorize("user")]
        public int Resource2 { get; }
        [Authorize]
        public int Resource3 { get; }


        private void InitializePrincipal()
        {
            ApplicationIdentity applicationIdentity = new(new List<Claim> { new Claim(ClaimTypes.Name, "Adi"), new Claim(ClaimTypes.Role, "admin") }, "password");
            Thread.CurrentPrincipal = new ApplicationPrincipal(applicationIdentity);
        }
        private void InitializeAnonymousPrincipal()
        {
            Thread.CurrentPrincipal = new ApplicationPrincipal(new ApplicationIdentity());
        }

        [TestMethod]
        [Authorize("admin")]
        public void CanAcceptPermission()
        {
            InitializePrincipal();
            AuthorizationManager authorizationManager = new();
            Assert.IsTrue(authorizationManager.CheckPermission());
        }

        [TestMethod]
        [Authorize]
        public void CanAcceptPermissionEmptyRoles()
        {
            InitializePrincipal();
            AuthorizationManager authorizationManager = new();
            Assert.IsTrue(authorizationManager.CheckPermission());
        }

        [TestMethod]
        [Authorize("user")]
        public void CanRefusePermission()
        {
            InitializePrincipal();
            AuthorizationManager authorizationManager = new();
            Assert.IsFalse(authorizationManager.CheckPermission());
        }

        [TestMethod]
        public void CanAcceptResourcePermission()
        {
            InitializePrincipal();
            AuthorizationManager authorizationManager = new();
            Assert.IsTrue(authorizationManager.HasPermission<AuthorizaztionManagerTest>(nameof(Resource1)));
        }

        [TestMethod]
        public void CanAcceptResourcePermissionEmptyRoles()
        {
            InitializePrincipal();
            AuthorizationManager authorizationManager = new();
            Assert.IsTrue(authorizationManager.HasPermission<AuthorizaztionManagerTest>(nameof(Resource3)));
        }

        [TestMethod]
        public void CanRefuseResourcePermission()
        {
            InitializePrincipal();
            AuthorizationManager authorizationManager = new();
            Assert.IsFalse(authorizationManager.HasPermission<AuthorizaztionManagerTest>(nameof(Resource2)));
        }

        [TestMethod]
        public void CanAcceptRole()
        {
            InitializePrincipal();
            AuthorizationManager authorizationManager = new();
            Assert.IsTrue(authorizationManager.IsInRole("admin"));
        }
        [TestMethod]
        public void CanRefuseRole()
        {
            InitializePrincipal();
            AuthorizationManager authorizationManager = new();
            Assert.IsFalse(authorizationManager.IsInRole("user"));
        }

        [TestMethod]
        [Authorize]
        public void CanRefuseIfNotAuthenticated()
        {
            InitializeAnonymousPrincipal();
            AuthorizationManager authorizationManager = new();
            Assert.IsFalse(authorizationManager.CheckPermission());
        }
    }
}
