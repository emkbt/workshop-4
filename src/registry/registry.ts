import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";

// Type representing a node in the registry
export type Node = { nodeId: number; pubKey: string };

// Type representing the request body to register a node
export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

// Type representing the response body to get the node registry
export type GetNodeRegistryBody = {
  nodes: Node[];
};

/**
 * Function to launch the registry server.
 * Registers nodes and provides node registry to other components.
 * @returns The created express server.
 */
export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());
  let nodes: Node[] = [];

  // Status route to check if the registry is live
  _registry.get("/status", (req, res) => {
    res.send("live");
  });

  // Route to register a node
  _registry.post("/registerNode", (req, res) => {
    const { nodeId, pubKey }: RegisterNodeBody = req.body;

    // Check if the node is already registered
    const nodeExists = nodes.find(node => node.nodeId === nodeId);
    if (nodeExists) {
      return res.status(400).json({ message: "Node already registered." });
    }

    nodes.push({ nodeId, pubKey });
    return res.status(201).json({ message: "Node registered successfully." });
  });
  
  // Route to get the node registry
  _registry.get("/getNodeRegistry", (req: Request, res: Response) => {
    const payload: GetNodeRegistryBody = {
      nodes: nodes
    };

    res.json(payload);
  }); 

  // Start listening on the registry port
  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`Registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}