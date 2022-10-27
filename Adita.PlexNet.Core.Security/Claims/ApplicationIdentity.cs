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

using System.Security.Claims;
using System.Security.Principal;

namespace Adita.PlexNet.Core.Security.Claims
{
    /// <summary>
    /// An <see cref="IIdentity"/> implementation for application user identity that support multiple <see cref="Claim"/>s-based.
    /// </summary>
    public class ApplicationIdentity : IIdentity
    {
        #region Constructors
        /// <summary>
        /// Initialize a new instance of <see cref="ApplicationIdentity"/>.
        /// </summary>
        public ApplicationIdentity(){}
        /// <summary>
        /// Initialize a new instance of <see cref="ApplicationIdentity"/>.
        /// </summary>
        /// <param name="authenticationType">The type of authentication used.</param>
        public ApplicationIdentity(string authenticationType)
        {
            AuthenticationType = authenticationType;
        }
        /// <summary>
        /// Initialize a new instance of <see cref="ApplicationIdentity"/>.
        /// </summary>
        /// <param name="authenticationType">The type of authentication used.</param>
        /// <param name="nameType">The claim type to use for name claims.</param>
        /// <param name="roleType">The claim type to use for role claims.</param>
        public ApplicationIdentity(string authenticationType, string nameType, string roleType)
        {
            AuthenticationType = authenticationType;
            NameClaimType = nameType;
            RoleClaimType = roleType;
        }
        /// <summary>
        /// Initialize a new instance of <see cref="ApplicationIdentity"/>.
        /// </summary>
        /// <param name="claims">The claims with which to populate the claims identity.</param>
        /// <param name="authenticationType">The type of authentication used.</param>
        public ApplicationIdentity(IEnumerable<Claim> claims, string authenticationType)
        {
            Claims = new List<Claim>(claims);
            AuthenticationType = authenticationType;
        }
        /// <summary>
        /// Initialize a new instance of <see cref="ApplicationIdentity"/>.
        /// </summary>
        /// <param name="claims">The claims with which to populate the claims identity.</param>
        /// <param name="authenticationType">The type of authentication used.</param>
        /// <param name="nameType">The claim type to use for name claims.</param>
        /// <param name="roleType">The claim type to use for role claims.</param>
        public ApplicationIdentity(IEnumerable<Claim> claims, string authenticationType, string nameType, string roleType)
        {
            Claims = new List<Claim>(claims);
            AuthenticationType = authenticationType;
            NameClaimType = nameType;
            RoleClaimType = roleType;
        }
        #endregion Constructors

        #region Public properties
        /// <inheritdoc/>
        public string? AuthenticationType { get; }
        /// <inheritdoc/>
        public bool IsAuthenticated { get { return !string.IsNullOrWhiteSpace(AuthenticationType); } }
        /// <summary>
        /// Gets a value that indicates whether the user account is identified as an anonymous account by the system.
        /// </summary>
        /// <value><see langword="true"/> if the user account is an anonymous account; otherwise, <see langword="false"/>.</value>
        public bool IsAnonymous { get { return string.IsNullOrWhiteSpace(Name); } }
        /// <inheritdoc/>
        public string? Name
        {
            get { return Claims.FirstOrDefault(o => o.Type == NameClaimType)?.Value; }
        }
        /// <summary>
        /// Gets the claims associated with this <see cref="ApplicationIdentity"/>.
        /// </summary>
        public IList<Claim> Claims { get; } = new List<Claim>();
        /// <summary>
        /// Gets the claim type that is used to determine which claims provide the value for the <see cref="Name"/> property of this <see cref="ApplicationIdentity"/>,
        /// default to <see cref="ClaimTypes.Name"/>.
        /// </summary>
        public string NameClaimType { get; } = ClaimTypes.Name;
        /// <summary>
        /// Gets the claim type that will be interpreted as a role among the claims in this <see cref="ApplicationIdentity"/>,
        /// default to <see cref="ClaimTypes.Role"/>.
        /// </summary>
        public string RoleClaimType { get; } = ClaimTypes.Role;
        #endregion Public properties

        #region Public methods
        /// <summary>
        /// Adds a single <see cref="Claim"/> to this <see cref="ApplicationIdentity"/>.
        /// </summary>
        /// <param name="claim">The <see cref="Claim"/> to add.</param>
        /// <exception cref="ArgumentNullException"><paramref name="claim"/> is <see langword="null"/></exception>
        public void AddClaim(Claim claim)
        {
            if (claim is null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            Claims.Add(claim);
        }
        /// <summary>
        /// Adds specified <paramref name="claims"/> to this <see cref="ApplicationIdentity"/>.
        /// </summary>
        /// <param name="claims">The list of <see cref="Claim"/> to add.</param>
        /// <exception cref="ArgumentNullException"><paramref name="claims"/>is <see langword="null"/></exception>
        public void AddClaims(IEnumerable<Claim> claims)
        {
            if (claims is null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            foreach (var claim in claims)
            {
                Claims.Add(claim);
            }
        }
        /// <summary>
        /// Retrieves all of the <see cref="Claim"/>s that match a specified condition.
        /// </summary>
        /// <param name="match">The function that performs the matching logic.</param>
        /// <returns>The matching <see cref="Claim"/>s. The list is read-only.</returns>
        public IEnumerable<Claim> FindAll(Predicate<Claim> match)
        {
            return Claims.Where(p => match(p)).ToList().AsReadOnly();
        }
        /// <summary>
        /// Determines whether current <see cref="ApplicationIdentity"/> 
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

            return Claims.Any(p => p.Type == type && p.Value == value);
        }
        /// <summary>
        /// Determines whether current <see cref="ApplicationIdentity"/> 
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

            return Claims.Any(p => match(p));
        }
        /// <summary>
        /// Attempts to remove a <see cref="Claim"/> from current <see cref="ApplicationIdentity"/>.
        /// </summary>
        /// <param name="claim">The claim to remove.</param>
        /// <returns>Wheter specified <paramref name="claim"/> has removed.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="claim"/> is <see langword="null"/></exception>
        public bool RemoveClaim(Claim claim)
        {
            if (claim is null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            return Claims.Remove(claim);
        }
        #endregion Public methods
    }
}
