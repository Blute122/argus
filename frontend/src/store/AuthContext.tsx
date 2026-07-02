import { createContext, useContext, useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { cancelProtectedRequests, getMe, setAuthToken } from '../services/api';

type User = {
  id: number;
  username: string;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
};

type AuthContextType = {
  user: User | null;
  token: string | null;
  login: (token: string, user: User) => void;
  logout: () => void;
  isAuthenticated: boolean;
  isLoading: boolean;
};

const AuthContext = createContext<AuthContextType>({
  user: null,
  token: null,
  login: () => {},
  logout: () => {},
  isAuthenticated: false,
  isLoading: true,
});

export const useAuth = () => useContext(AuthContext);

const readStoredUser = () => {
  const stored = localStorage.getItem('soc_user');
  if (!stored) return null;

  try {
    return JSON.parse(stored) as User;
  } catch {
    localStorage.removeItem('soc_user');
    return null;
  }
};

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(() =>
    localStorage.getItem('soc_token') ? readStoredUser() : null
  );
  const [token, setToken] = useState<string | null>(() => localStorage.getItem('soc_token'));
  const [isLoading, setIsLoading] = useState(() => Boolean(localStorage.getItem('soc_token')));

  const clearSession = () => {
    cancelProtectedRequests();
    localStorage.removeItem('soc_token');
    localStorage.removeItem('soc_user');
    setAuthToken(null);
    setToken(null);
    setUser(null);
  };

  useEffect(() => {
    const storedToken = localStorage.getItem('soc_token');

    if (!storedToken) {
      localStorage.removeItem('soc_user');
      setAuthToken(null);
      return;
    }

    setAuthToken(storedToken);

    getMe()
      .then((res) => {
        const currentUser = res.data as User;
        localStorage.setItem('soc_user', JSON.stringify(currentUser));
        setToken(storedToken);
        setUser(currentUser);
      })
      .catch(() => {
        clearSession();
      })
      .finally(() => {
        setIsLoading(false);
      });
  }, []);

  useEffect(() => {
    const handleLogout = () => {
      clearSession();
      setIsLoading(false);
    };

    window.addEventListener('soc:logout', handleLogout);
    return () => window.removeEventListener('soc:logout', handleLogout);
  }, []);

  const loginFn = (newToken: string, newUser: User) => {
    localStorage.setItem('soc_token', newToken);
    localStorage.setItem('soc_user', JSON.stringify(newUser));
    setAuthToken(newToken);
    setToken(newToken);
    setUser(newUser);
  };

  const logout = () => {
    clearSession();
  };

  return (
    <AuthContext.Provider
      value={{ user, token, login: loginFn, logout, isAuthenticated: !!token, isLoading }}
    >
      {children}
    </AuthContext.Provider>
  );
}
