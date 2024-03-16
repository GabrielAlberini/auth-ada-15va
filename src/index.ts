// Sistema de login
// ver lista de usuarios - ocutar data sensible
// register -> registrar un nuevo user - verificar si no existe, hashear la pass
// login -> logear un user - generar el token
// actualizar un user
// borrar un user

import express, { Request, Response, NextFunction } from "express";
import users from "./database/users.json";
import jsonfile from "jsonfile";
import crypto from "node:crypto";

const app = express();

// Activa la posibilidad de usar req.body
app.use(express.json());

// Middleware -> función a mitad de camino, valida procesos.
const validateAuth = (req: Request, res: Response, next: NextFunction) => {
  // Enviar token por el cuerpo de la petición
  //const { token } = req.body;

  // Enviar token por el header (forma no oficial)
  // const { authorization } = req.headers;

  const token = req.get("Authorization");
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  const exists = users.find((u) => u.token === token);
  if (!exists) return res.status(401).json({ error: "Unauthorized" });

  next();
};

const PORT = process.env.PORT || 1234;

app.get("/api", (req, res) => {
  res.json({
    version: "1.0.0",
    author: "gabrielalberini",
    paths: {
      info: "/api",
      users: "/api/users",
    },
  });
});

app.get("/api/users", validateAuth, (req, res) => {
  res.json(users);
});

app.post("/api/users/register", (req, res) => {
  const { username, password, email } = req.body;
  users.push({ username, password, email, token: "" });
  jsonfile.writeFileSync("./src/database/users.json", users);
  res.status(201).json({ username, email });
});

app.post("/api/users/login", (req, res) => {
  const { username, password } = req.body;

  const user = users.find((u) => u.username === username);

  if (!user) return res.status(404).json({ error: "User not found..." });
  if (user.password !== password)
    return res.status(400).json({ error: "Bad request..." });

  // AWS
  const token = crypto.randomUUID();
  user.token = token;
  jsonfile.writeFileSync("./src/database/users.json", users);

  res.status(201).json({ message: "User logged", token: token });
});

app.delete("/api/users/logout", validateAuth, (req, res) => {
  const { username } = req.body;
  const user = users.find((u) => u.username === username);

  if (!user) return res.status(404).json({ error: "User not found" });

  user.token = "";

  jsonfile.writeFileSync("./src/database/users.json", users);

  res.status(201).json({ message: "User logout" });
});

app.use("*", (req, res) => {
  res.status(404).json({ error: "Resource not found" });
});

app.listen(PORT, () => {
  console.log(`Server listening on port http://localhost:${PORT}`);
});
