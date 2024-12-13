package forwardproxy

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type LdapConfig struct {
	Url        *url.URL      `json:"url,omitempty"`
	BaseDN     string        `json:"base_dn,omitempty"`
	UserSuffix string        `json:"user_suffix,omitempty"`
	UserGroup  string        `json:"user_group,omitempty"`
	FilterDN   string        `json:"filter_dn,omitempty"`
	BindDN     string        `json:"bind_dn,omitempty"`
	BindPasswd string        `json:"bind_passwd,omitempty"`
	Timeout    time.Duration `json:"timeout,omitempty"`
	PoolSize   int           `json:"pool_size,omitempty"`
	CacheUse   bool          `json:"cache_use,omitempty"`
	CacheTTL   time.Duration `json:"cache_ttl,omitempty"`
}

type Ldap struct {
	Pool         chan ldap.Client
	UserCacheMap *userCache
	SessionMap   sync.Map
	Mu           sync.Mutex
}

func (h *Handler) cacheUser(login, password string, inLdap bool) {
	if h.LdapConfig.CacheUse {
		go h.Ldap.UserCacheMap.add(
			login, password, inLdap, h.LdapConfig.CacheTTL,
		)
	}
}

func (h *Handler) ldapInit() error {
	h.Ldap = &Ldap{}
	h.Ldap.Pool = make(chan ldap.Client, h.LdapConfig.PoolSize)
	if h.LdapConfig.CacheUse {
		h.Ldap.UserCacheMap = newUserCacheMap(h.logger)
	}

	return nil
}

func (h *Handler) getConnection() (ldap.Client, error) {
	var client ldap.Client
	select {
	case client = <-h.Ldap.Pool:
		if err := client.Bind(h.LdapConfig.BindDN, h.LdapConfig.BindPasswd); err == nil {
			return client, nil
		}
		client.Close()
	default:
	}

	var err error
	client, err = ldap.DialURL(h.LdapConfig.Url.String())
	if err != nil {
		return nil, fmt.Errorf(
			"Dial to %q failed: %v", h.LdapConfig.Url.String(), err,
		)
	}

	if err := client.Bind(h.LdapConfig.BindDN, h.LdapConfig.BindPasswd); err != nil {
		client.Close()
		return nil, fmt.Errorf(
			"Bind with %q failed: %v", h.LdapConfig.BindDN, err,
		)
	}

	return client, nil
}

func (h *Handler) stashConnection(client ldap.Client) {
	select {
	case h.Ldap.Pool <- client:
		return
	default:
		client.Close()
		return
	}
}

func (h *Handler) verifyLdapLoginAndPassword(creds string) error {
	pair := strings.SplitN(creds, ":", 2)
	if len(pair) != 2 {
		return fmt.Errorf("Error parsing creds %q", creds)
	}

	login := pair[0]
	password := pair[1]

	lock, _ := func() (interface{}, bool) {
		h.Ldap.Mu.Lock()
		defer h.Ldap.Mu.Unlock()
		return h.Ldap.SessionMap.LoadOrStore(login, &sync.Mutex{})
	}()

	session := lock.(*sync.Mutex)
	session.Lock()

	defer func() {
		session.Unlock()
		h.Ldap.Mu.Lock()
		defer h.Ldap.Mu.Unlock()
		h.Ldap.SessionMap.Delete(login)
	}()

	if h.LdapConfig.CacheUse {
		inCache, allowed := h.Ldap.UserCacheMap.get(login, password)
		if inCache {
			if allowed {
				return nil
			} else {
				return fmt.Errorf("Block user %q from deny list", login)
			}
		}
	}

	client, err := h.getConnection()
	if err != nil {
		return fmt.Errorf(
			"Failed to obtain Ldap connection from pool: %v", err,
		)
	}
	defer h.stashConnection(client)

	ldapRequest := ldap.NewSearchRequest(
		h.LdapConfig.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0,
		int(h.LdapConfig.Timeout.Seconds()),
		false,
		fmt.Sprintf(
			h.LdapConfig.FilterDN,
			ldap.EscapeFilter(login),
			ldap.EscapeFilter(h.LdapConfig.UserGroup),
		),
		[]string{"dn"},
		nil,
	)

	sr, err := client.Search(ldapRequest)
	if err != nil {
		return fmt.Errorf(
			fmt.Sprintf("Failed Ldap search for user %q: %v", login, err),
		)
	}

	if len(sr.Entries) > 1 {
		return fmt.Errorf("Too many Ldap results found for %q", login)
	}
	if len(sr.Entries) == 0 {
		go h.cacheUser(login, password, false)
		return fmt.Errorf("No Ldap results found for %q", login)
	}

	loginBindDN := fmt.Sprintf("CN=%s,%s", login, h.LdapConfig.UserSuffix)
	err = client.Bind(loginBindDN, password)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			go h.cacheUser(login, password, false)
			return fmt.Errorf("Failed Ldap authentication with user %q", login)
		}
		return fmt.Errorf("Ldap Bind with user %q failed: %v", login, err)
	}

	h.cacheUser(login, password, true)
	return nil
}
