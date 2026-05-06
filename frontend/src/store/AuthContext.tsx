import { createContext, useContext, useState } from 'react';
import type { ReactNode } from 'react';

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
};

const AuthContext = createContext<AuthContextType>({
  user: null, token: null, login: () => {}, logout: () => {}, isAuthenticated: false,
});

export const useAuth = () => useContext(AuthContext);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(() => {
    const stored = localStorage.getItem('soc_user');
    return stored ? JSON.parse(stored) : null;
  });
  const [token, setToken] = useState<string | null>(() => localStorage.getItem('soc_token'));

  const loginFn = (newToken: string, newUser: User) => {
    localStorage.setItem('soc_token', newToken);
    localStorage.setItem('soc_user', JSON.stringify(newUser));
    setToken(newToken);
    setUser(newUser);
  };

  const logout = () => {
    localStorage.removeItem('soc_token');
    localStorage.removeItem('soc_user');
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, token, login: loginFn, logout, isAuthenticated: !!token }}>
      {children}
    </AuthContext.Provider>
  );
}
