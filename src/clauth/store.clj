(ns clauth.store)

(defprotocol Store
  "Store objects"
  (fetch [e k]
    "Find the item based on a key.")
  (revoke! [e k]
    "Invalidate or remove the item based on a key")
  (store! [e key_param item]
    "Store the given map using the value of the kw key_param and return it.")
  (entries [e]
    "sequence of entries")
  (reset-store! [e]
    "clear all entries"))

(defrecord MemoryStore [data]
  Store
  (fetch [this t] (@data t))
  (revoke! [this t] (swap! data dissoc t))
  (store! [this key_param item]
    (do
      (swap! data assoc (key_param item) item)
      item))
  (entries [this] (or (vals @data) []))
  (reset-store! [this] (reset! data {})))

(defn create-memory-store
  "Create a memory token store"
  ([] (create-memory-store {}))
  ([data]
     (MemoryStore. (atom data))))

