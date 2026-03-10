import { describe, it, expect } from 'vitest';
import { HttpHeaders } from './headers';

describe('HttpHeaders', () => {

   it('constructs from Record<string, string>', () => {
      const headers = new HttpHeaders({ 'Content-Type': 'application/json' });

      expect(headers.get('content-type')).toBe('application/json');
   });

   it('constructs from Record<string, string[]>', () => {
      const headers = new HttpHeaders({ 'Set-Cookie': [ 'a=1', 'b=2' ] });

      expect(headers.getAll('set-cookie')).toEqual([ 'a=1', 'b=2' ]);
   });

   it('get() is case-insensitive', () => {
      const headers = new HttpHeaders({ 'Content-Type': 'text/html' });

      expect(headers.get('CONTENT-TYPE')).toBe('text/html');
      expect(headers.get('content-type')).toBe('text/html');
      expect(headers.get('Content-Type')).toBe('text/html');
   });

   it('get() returns null for missing headers', () => {
      const headers = new HttpHeaders();

      expect(headers.get('x-missing')).toBeNull();
   });

   it('set() replaces existing values', () => {
      const headers = new HttpHeaders({ 'X-Foo': [ 'a', 'b' ] });

      headers.set('X-Foo', 'c');
      expect(headers.getAll('x-foo')).toEqual([ 'c' ]);
   });

   it('append() adds to existing values', () => {
      const headers = new HttpHeaders({ 'X-Foo': 'a' });

      headers.append('X-Foo', 'b');
      expect(headers.getAll('x-foo')).toEqual([ 'a', 'b' ]);
   });

   it('append() creates new header if not present', () => {
      const headers = new HttpHeaders();

      headers.append('X-New', 'val');
      expect(headers.get('x-new')).toBe('val');
   });

   it('has() checks existence case-insensitively', () => {
      const headers = new HttpHeaders({ 'Authorization': 'Bearer token' });

      expect(headers.has('authorization')).toBe(true);
      expect(headers.has('AUTHORIZATION')).toBe(true);
      expect(headers.has('x-missing')).toBe(false);
   });

   it('delete() removes headers case-insensitively', () => {
      const headers = new HttpHeaders({ 'X-Remove': 'val' });

      headers.delete('X-REMOVE');
      expect(headers.has('x-remove')).toBe(false);
   });

   it('forEach() iterates all name-value pairs', () => {
      const headers = new HttpHeaders({ 'a': [ '1', '2' ], 'b': '3' }),
            pairs: Array<[string, string]> = [];

      headers.forEach((value, name) => {
         pairs.push([ name, value ]);
      });

      expect(pairs).toEqual([
         [ 'a', '1' ],
         [ 'a', '2' ],
         [ 'b', '3' ],
      ]);
   });

   it('entries() returns flattened name-value pairs', () => {
      const headers = new HttpHeaders({ 'a': [ '1', '2' ] }),
            entries = Array.from(headers.entries());

      expect(entries).toEqual([
         [ 'a', '1' ],
         [ 'a', '2' ],
      ]);
   });

   it('is iterable via Symbol.iterator', () => {
      const headers = new HttpHeaders({ 'x-test': 'val' }),
            entries = Array.from(headers);

      expect(entries).toEqual([ [ 'x-test', 'val' ] ]);
   });

   it('keys() returns header names', () => {
      const headers = new HttpHeaders({ 'A': '1', 'B': '2' }),
            keys = Array.from(headers.keys());

      expect(keys).toEqual([ 'a', 'b' ]);
   });

   it('values() returns first value per header', () => {
      const headers = new HttpHeaders({ 'a': [ 'first', 'second' ], 'b': 'only' }),
            values = Array.from(headers.values());

      expect(values).toEqual([ 'first', 'only' ]);
   });

   it('toRecord() joins multi-value headers with comma per RFC 9110', () => {
      const headers = new HttpHeaders({ 'a': [ '1', '2' ], 'b': '3' });

      expect(headers.toRecord()).toEqual({ a: '1, 2', b: '3' });
   });

   it('handles empty initialization', () => {
      const headers = new HttpHeaders();

      expect(headers.get('anything')).toBeNull();
      expect(Array.from(headers.entries())).toEqual([]);
   });

});
