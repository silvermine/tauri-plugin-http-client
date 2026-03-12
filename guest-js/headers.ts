/**
 * Case-insensitive HTTP headers collection with multi-value support.
 *
 * Header names are normalized to lowercase for consistent access.
 */
export class HttpHeaders implements Iterable<[string, string]> {

   private _map: Map<string, string[]> = new Map();

   public constructor(init?: Record<string, string | string[]>) {
      if (init) {
         for (const [ name, value ] of Object.entries(init)) {
            if (Array.isArray(value)) {
               this._map.set(name.toLowerCase(), [ ...value ]);
            } else {
               this._map.set(name.toLowerCase(), [ value ]);
            }
         }
      }
   }

   /**
    * Returns the first value for the given header name, or `null` if not present.
    */
   public get(name: string): string | null {
      const values = this._map.get(name.toLowerCase());

      return values ? values[0] : null;
   }

   /**
    * Returns all values for the given header name.
    */
   public getAll(name: string): string[] {
      return this._map.get(name.toLowerCase()) ?? [];
   }

   /**
    * Sets the header to a single value, replacing any existing values.
    */
   public set(name: string, value: string): void {
      this._map.set(name.toLowerCase(), [ value ]);
   }

   /**
    * Appends a value to the header (creates the header if it doesn't exist).
    */
   public append(name: string, value: string): void {
      const key = name.toLowerCase(),
            existing = this._map.get(key);

      if (existing) {
         existing.push(value);
      } else {
         this._map.set(key, [ value ]);
      }
   }

   /**
    * Returns `true` if the header exists.
    */
   public has(name: string): boolean {
      return this._map.has(name.toLowerCase());
   }

   /**
    * Removes the header.
    */
   public delete(name: string): void {
      this._map.delete(name.toLowerCase());
   }

   /**
    * Iterates over all headers, calling `fn` for each name-value pair.
    * Multi-value headers call `fn` once per value.
    */
   public forEach(fn: (value: string, name: string, headers: HttpHeaders) => void): void {
      for (const [ name, values ] of this._map) {
         for (const value of values) {
            fn(value, name, this);
         }
      }
   }

   /**
    * Returns an iterator of `[name, value]` pairs. Multi-value headers
    * produce one entry per value.
    */
   public entries(): IterableIterator<[string, string]> {
      const pairs: Array<[string, string]> = [];

      for (const [ name, values ] of this._map) {
         for (const value of values) {
            pairs.push([ name, value ]);
         }
      }

      return pairs[Symbol.iterator]();
   }

   /**
    * Returns an iterator of header names.
    */
   public keys(): IterableIterator<string> {
      return this._map.keys();
   }

   /**
    * Returns an iterator of first values for each header.
    */
   public values(): IterableIterator<string> {
      const vals: string[] = [];

      for (const values of this._map.values()) {
         vals.push(values[0]);
      }

      return vals[Symbol.iterator]();
   }

   public [Symbol.iterator](): Iterator<[string, string]> {
      return this.entries();
   }

   /**
    * Converts headers to a plain `Record<string, string>`, joining
    * multi-value headers with `", "` per RFC 9110 Section 5.3.
    *
    * Used when serializing headers for the IPC bridge.
    *
    * **Note:** This conversion is lossy for headers that must not be
    * combined, most notably `Set-Cookie` (RFC 9110 Section 5.3 explicitly
    * excludes it from the combining rule). Use `toMultiRecord()` when you
    * need to preserve each value separately.
    */
   public toRecord(): Record<string, string> {
      const record: Record<string, string> = {};

      for (const [ name, values ] of this._map) {
         record[name] = values.join(', ');
      }

      return record;
   }

   /**
    * Converts headers to a `Record<string, string[]>`, preserving all
    * values for every header as a separate array entry.
    *
    * Prefer this over `toRecord()` when the caller needs to handle headers
    * that must not be combined, such as `Set-Cookie`.
    */
   public toMultiRecord(): Record<string, string[]> {
      const record: Record<string, string[]> = {};

      for (const [ name, values ] of this._map) {
         record[name] = [ ...values ];
      }

      return record;
   }

}
