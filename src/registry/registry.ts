import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";

export type Node = { nodeId: number; pubKey: string };

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());
  let nodes: Node[] = [];

  // Implement the status route
  _registry.get("/status", (req, res) => {
    res.send("live");
  });

  _registry.post("/registerNode", (req, res) => {
    const { nodeId, pubKey }: RegisterNodeBody = req.body;
  
    const nodeExists = nodes.find(node => node.nodeId === nodeId);
    if (nodeExists) {
      return res.status(400).json({ message: "Node already registered." });
    }

    nodes.push({ nodeId, pubKey });
    return res.status(201).json({ message: "Node registered successfully." });
  });
  
  _registry.get("/getNodeRegistry", (req: Request, res: Response) => {
    const payload: GetNodeRegistryBody = {
      nodes: nodes
    };
  
    res.json(payload);
  });

  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}
