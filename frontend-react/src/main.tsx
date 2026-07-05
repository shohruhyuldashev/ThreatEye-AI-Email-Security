import { StrictMode, createElement } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, Navigate, RouterProvider, type RouteObject } from "react-router-dom";
import { AuthProvider } from "./lib/auth";
import { RootLayout } from "./components/RootLayout";
import { RequireAuth, RequireRole } from "./components/guards";
import { Login } from "./pages/Login";
import { APP_ROUTES } from "./routes";

// Build the router declaratively from the logical route table. Protected pages live
// under one layout route; role-restricted pages are additionally wrapped in a guard.
const protectedChildren: RouteObject[] = APP_ROUTES.map((r) => {
  const page = createElement(r.Component);
  const element = r.roles ? <RequireRole roles={r.roles}>{page}</RequireRole> : page;
  return r.index ? { index: true, element } : { path: r.path, element };
});

const router = createBrowserRouter([
  { path: "/login", element: <Login /> },
  {
    element: (
      <RequireAuth>
        <RootLayout />
      </RequireAuth>
    ),
    children: protectedChildren,
  },
  { path: "*", element: <Navigate to="/" replace /> },
]);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <AuthProvider>
      <RouterProvider router={router} />
    </AuthProvider>
  </StrictMode>,
);
