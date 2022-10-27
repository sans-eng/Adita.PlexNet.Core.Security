//MIT License

//Copyright (c) 2022 Adita

//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:

//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.

//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.

using Adita.PlexNet.Core.Security.Claims;
using System.Security.Claims;
using System.Security.Principal;

namespace Adita.PlexNet.Core.Security.Principals
{
    /// <summary>
    /// An <see cref="IPrincipal"/> implementation that supports multiple claims-based identities for <see cref="ApplicationIdentity"/>.
    /// </summary>
    public class ApplicationPrincipal : IPrincipal
    {
        #region Private fields
        private ApplicationIdentity _identity;
        #endregion Private fields

        #region Constructors
        /// <summary>
        /// Initialize a new instance of <see cref="ApplicationIdentity"/> using specified <paramref name="identity"/>.
        /// </summary>
        /// <param name="identity">An <see cref="ApplicationIdentity"/> to associated.</param>
        /// <exception cref="ArgumentNullException"><paramref name="identity"/> is <see langword="null"/></exception>
        public ApplicationPrincipal(ApplicationIdentity identity)
        {
            _identity = identity ?? throw new ArgumentNullException(nameof(identity));
        }
        #endregion Constructors

        #region Public properties
        /// <summary>
        /// Gets the <see cref="IIdentity"/> of the current <see cref="ApplicationPrincipal"/>.
        /// </summary>
        /// <returns
        /// >The <see cref="IIdentity" /> object associated with the current <see cref="ApplicationPrincipal"/>.
        /// </returns>
        public IIdentity Identity
        {
            get { return _identity; }
        }
        #endregion Public properties

        #region Events
        /// <summary>
        /// Occurs when identity changed.
        /// </summary>
        public event EventHandler<IIdentity>? IdentityChanged;
        #endregion Events

        #region Public methods
        /// <summary>
        /// Set current <see cref="ApplicationPrincipal"/> using specified <paramref name="identity"/>.
        /// </summary>
        /// <param name="identity">An <see cref="ApplicationIdentity"/> to set.</param>
        public void SetIdentity(ApplicationIdentity identity)
        {
            _identity = identity;
            IdentityChanged?.Invoke(this, _identity);
        }
        /// <summary>
        /// Determines whether the <see cref="IIdentity"/> that associated with
        /// current <see cref="ApplicationPrincipal"/>
        /// is in the specified <paramref name="role"/>.
        /// </summary>
        /// <param name="role">The name of the role for which to check membership.</param>
        /// <returns>
        ///  <see langword="true" /> if the current principal is a member of the specified role; otherwise, <see langword="false" />.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="role"/> is <see langword="null"/></exception>
        public bool IsInRole(string role)
        {
            if (role is null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            return _identity.HasClaim(_identity.RoleClaimType, role);
        }
        /// <summary>
        /// Determines whether the <see cref="IIdentity"/> associated with current <see cref="ApplicationPrincipal"/> 
        /// has a <see cref="Claim"/> with the specified <paramref name="type"/> and <paramref name="value"/>.
        /// </summary>
        /// <param name="type">The type of the <see cref="Claim"/> to match.</param>
        /// <param name="value">The value of the <see cref="Claim"/> to match.</param>
        /// <returns><see langword="true"/> if a match is found; otherwise, <see langword="false"/>.</returns>
        /// <exception cref="ArgumentException"><paramref name="type"/> or <paramref name="value"/> is <see langword="null"/></exception>
        public bool HasClaim(string type, string value)
        {
            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException($"'{nameof(type)}' cannot be null or empty.", nameof(type));
            }

            if (string.IsNullOrEmpty(value))
            {
                throw new ArgumentException($"'{nameof(value)}' cannot be null or empty.", nameof(value));
            }

            return _identity.HasClaim(type, value);
        }
        /// <summary>
        /// Determines whether the <see cref="IIdentity"/> associated with current
        /// <see cref="ApplicationPrincipal"/>
        /// has a <see cref="Claim"/> that is matched by the specified <paramref name="match"/>.
        /// </summary>
        /// <param name="match">The function that performs the matching logic.</param>
        /// <returns><see langword="true"/> if a match is found; otherwise, <see langword="false"/>.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="match"/> is <see langword="null"/></exception>
        public bool HasClaim(Predicate<Claim> match)
        {
            if (match is null)
            {
                throw new ArgumentNullException(nameof(match));
            }

            return _identity.HasClaim(match);
        }
        #endregion Public methods
    }
}
