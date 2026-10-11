// MongoDB access. Collections:
//   source_files   one document per upload (or, with connectors, per pull); the latest active one per kind feeds runs
//   settings       one document: the client's rules and thresholds over the defaults
//   runs           one document per assessment run: the dated snapshot (service, sources used, thresholds, scenarios,
//                  rating, risks, DR results), with its assets embedded
//   check_results  one document per check result (asset- or application-level), with its evidence rows
//   counters       sequences for the short numeric ids used in URLs (/runs/5/result/123)
import { MongoClient } from "mongodb";

export async function connect(uri, dbName) {
  const client = new MongoClient(uri);
  await client.connect();
  const db = client.db(dbName);
  await Promise.all([
    db.collection("source_files").createIndex({ kind: 1, active: 1, id: -1 }),
    db.collection("runs").createIndex({ id: 1 }, { unique: true }),
    db.collection("runs").createIndex({ service_name: 1, id: -1 }),
    db.collection("check_results").createIndex({ run_id: 1, id: 1 }),
  ]);
  return { client, db };
}

/** Next number in a named sequence (1, 2, 3, ...). */
export async function nextId(db, name, count = 1) {
  const res = await db.collection("counters").findOneAndUpdate(
    { _id: name }, { $inc: { seq: count } }, { upsert: true, returnDocument: "after" });
  return res.seq - count + 1; // first id of the reserved block
}
