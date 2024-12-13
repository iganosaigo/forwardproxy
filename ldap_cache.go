package forwardproxy

import (
	"fmt"
	"go.uber.org/zap"
	"sync"
	"time"
)

type user struct {
	login    string
	password string
	inLdap   bool
	Timer    *time.Timer
}

type userCache struct {
	mu     sync.Mutex
	data   map[string]*user
	logger *zap.Logger
}

func newUserCacheMap(logger *zap.Logger) *userCache {
	return &userCache{
		data:   make(map[string]*user),
		logger: logger,
	}
}

func (u *userCache) add(login, password string, inLdap bool, duration time.Duration) {
	u.mu.Lock()
	defer u.mu.Unlock()

	// no touching if cache is still valid.
	if item, exists := u.data[login]; exists && item.Timer != nil {
		return
	}

	timer := time.AfterFunc(duration, func() {
		u.delete(login)
	})

	u.data[login] = &user{
		login:    login,
		password: password,
		inLdap:   inLdap,
		Timer:    timer,
	}
	var msg string
	msgSuffix := " populated with login %q for %s"
	if inLdap {
		msg = "Cache Allow_List"
	} else {
		msg = "Cache Deny_List"
	}
	u.logger.Info(
		fmt.Sprintf(msg+msgSuffix, login, duration.String()),
	)
}

func (u *userCache) delete(login string) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if item, exists := u.data[login]; exists {
		if item.Timer != nil {
			item.Timer.Stop()
			item.Timer = nil
		}
		delete(u.data, login)
		u.logger.Info(fmt.Sprintf("Cache expired for login %q", login))
	}
}

func (u *userCache) get(login, password string) (inCache, allow bool) {
	u.mu.Lock()
	defer u.mu.Unlock()

	user, exists := u.data[login]
	if !exists {
		inCache, allow = false, false
	} else {
		if password != user.password {
			u.logger.Info(fmt.Sprintf(
				"Cached and provided passwords mismatch for login %q", login))
			inCache, allow = true, false
		} else {
			inCache, allow = true, user.inLdap
		}
	}
	return
}
