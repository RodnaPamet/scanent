/**
 * Address and CIDR parsing: strict in what it reads, exact at the boundaries.
 *
 *   1. An IPv4 literal is four plain decimal octets, or it is nothing.
 *   2. An IPv6 literal, with `::`, brackets and a v4-mapped tail.
 *   3. A CIDR is an address, a slash and a prefix that fits the family.
 *   4. Membership is by family and by bit, including a prefix inside a byte.
 *   5. A v4-mapped address is recognised as one.
 */
import { inCidr, isV4Mapped, parseAddress, parseCidr, type Cidr } from '../src/cidr';

const bytes = (text: string) => {
    const a = parseAddress(text);
    return a === null ? null : [...a];
};
const cidr = (text: string): Cidr => {
    const c = parseCidr(text);
    if (c === null) throw new Error(`expected ${text} to parse`);
    return c;
};
const within = (addr: string, block: string) => inCidr(parseAddress(addr)!, cidr(block));

describe('1. IPv4', () => {
    it.each([
        ['0.0.0.0', [0, 0, 0, 0]],
        ['10.0.0.1', [10, 0, 0, 1]],
        ['255.255.255.255', [255, 255, 255, 255]],
        ['  192.168.1.20  ', [192, 168, 1, 20]],
    ])('reads %s', (text, expected) => {
        expect(bytes(text)).toEqual(expected);
    });

    it.each([
        ['a leading zero', '010.1.1.1'],
        ['a leading zero in the last octet', '10.1.1.01'],
        ['three parts', '127.0.1'],
        ['two parts', '127.1'],
        ['five parts', '1.2.3.4.5'],
        ['an octet over 255', '256.1.1.1'],
        ['an octet of four digits', '1.2.3.1000'],
        ['an empty octet', '1..2.3'],
        ['a trailing dot', '1.2.3.4.'],
        ['a negative octet', '1.2.3.-4'],
        ['hexadecimal', '0x7f.0.0.1'],
        ['a single integer', '2130706433'],
        ['a host name', 'localhost'],
        ['a space inside', '1.2.3. 4'],
        ['nothing', ''],
    ])('refuses %s rather than normalising it', (_label, text) => {
        expect(parseAddress(text)).toBeNull();
    });
});

describe('2. IPv6', () => {
    it('reads a full address, in either case', () => {
        expect(bytes('2001:0DB8:0000:0000:0000:ff00:0042:8329')).toEqual([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0xff, 0, 0, 0x42, 0x83, 0x29]);
    });

    it.each([
        ['::', new Array(16).fill(0)],
        ['::1', [...new Array(15).fill(0), 1]],
        ['fe80::', [0xfe, 0x80, ...new Array(14).fill(0)]],
        ['2001:db8::8329', [0x20, 0x01, 0x0d, 0xb8, ...new Array(10).fill(0), 0x83, 0x29]],
        ['1:2:3:4:5:6:7::', [0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 0]],
    ])('expands %s', (text, expected) => {
        expect(bytes(text)).toEqual(expected);
    });

    it('reads a bracketed literal as the address inside the brackets', () => {
        expect(bytes('[::1]')).toEqual(bytes('::1'));
        expect(bytes(' [fd00::1] ')).toEqual(bytes('fd00::1'));
    });

    it('expands a v4-mapped tail to the same bytes as its hexadecimal spelling', () => {
        expect(bytes('::ffff:10.0.0.1')).toEqual(bytes('::ffff:a00:1'));
        expect(bytes('::ffff:169.254.169.254')).toEqual([...new Array(10).fill(0), 0xff, 0xff, 169, 254, 169, 254]);
        expect(bytes('64:ff9b::192.0.2.33')).toEqual([0, 0x64, 0xff, 0x9b, ...new Array(8).fill(0), 192, 0, 2, 33]);
        expect(bytes('0:0:0:0:0:ffff:1.2.3.4')).toEqual([...new Array(10).fill(0), 0xff, 0xff, 1, 2, 3, 4]);
    });

    it.each([
        ['a v4 tail with an octet over 255', '::ffff:256.0.0.1'],
        ['a v4 tail with a leading zero', '::ffff:010.0.0.1'],
        ['two compressions', '1::2::3'],
        ['too few groups without a compression', '1:2:3:4:5:6:7'],
        ['too many groups', '1:2:3:4:5:6:7:8:9'],
        ['a group of five digits', '12345::'],
        ['a group that is not hexadecimal', 'fe80::g'],
        ['a zone identifier', 'fe80::1%eth0'],
        ['an empty group', '1:2:3:4:5:6:7:'],
        ['a lone colon', ':'],
        ['empty brackets', '[]'],
        ['a v4 tail with too many groups before it', '1:2:3:4:5:6:7:1.2.3.4'],
    ])('refuses %s', (_label, text) => {
        expect(parseAddress(text)).toBeNull();
    });

    // A `::` among more than eight groups left a negative count to fill, and
    // `Array(-1)` throws: a parser that refuses must refuse by returning.
    it.each([
        ['nine groups around a compression', '1:2:3:4::5:6:7:8:9'],
        ['nine groups before a trailing compression', '1:2:3:4:5:6:7:8:9::'],
        ['nine groups after a leading compression', '::1:2:3:4:5:6:7:8:9'],
        ['many groups around a compression', `${'1:'.repeat(40)}:1`],
        ['a v4 tail that makes nine groups around a compression', '1:2:3:4::5:6:7:1.2.3.4'],
        ['the same, in brackets', '[1:2:3:4::5:6:7:8:9]'],
    ])('refuses %s without throwing', (_label, text) => {
        expect(() => parseAddress(text)).not.toThrow();
        expect(parseAddress(text)).toBeNull();
    });

    it('refuses a CIDR over such a literal without throwing', () => {
        expect(() => parseCidr('1:2:3:4::5:6:7:8:9/64')).not.toThrow();
        expect(parseCidr('1:2:3:4::5:6:7:8:9/64')).toBeNull();
    });
});

describe('3. a CIDR', () => {
    it('keeps the address, the prefix and the text it came from', () => {
        const c = cidr(' 10.20.0.0/16 ');
        expect([...c.bytes]).toEqual([10, 20, 0, 0]);
        expect(c.prefixBits).toBe(16);
        expect(c.source).toBe('10.20.0.0/16');
        expect(cidr('fd00::/8')).toMatchObject({ prefixBits: 8, source: 'fd00::/8' });
        expect(cidr('[fd00::]/8').bytes).toHaveLength(16);
    });

    it.each(['0.0.0.0/0', '10.0.0.1/32', '::/0', '::1/128', '::ffff:10.0.0.0/104'])('admits the whole range of prefixes: %s', (text) => {
        expect(parseCidr(text)).not.toBeNull();
    });

    it.each([
        ['no slash', '10.0.0.0'],
        ['nothing before the slash', '/8'],
        ['nothing after the slash', '10.0.0.0/'],
        ['a v4 prefix over 32', '10.0.0.0/33'],
        ['a v6 prefix over 128', 'fd00::/129'],
        ['a prefix of four digits', '10.0.0.0/0008'],
        ['a negative prefix', '10.0.0.0/-8'],
        ['a prefix that is not a number', '10.0.0.0/eight'],
        ['a netmask in place of a prefix', '10.0.0.0/255.0.0.0'],
        ['an address that does not parse', '10.0.0/8'],
        ['a lenient v4 address', '010.0.0.0/8'],
        ['a host name', 'example.com/24'],
        ['an empty string', ''],
    ])('refuses %s', (_label, text) => {
        expect(parseCidr(text)).toBeNull();
    });

    it('uses the last slash, so a second one cannot hide in the address', () => {
        expect(parseCidr('10.0.0.0/8/16')).toBeNull();
    });
});

describe('4. membership', () => {
    it('a /0 holds every address of its family, and none of the other', () => {
        expect(within('203.0.113.9', '0.0.0.0/0')).toBe(true);
        expect(within('2001:db8::1', '::/0')).toBe(true);
        expect(within('2001:db8::1', '0.0.0.0/0')).toBe(false);
        expect(within('203.0.113.9', '::/0')).toBe(false);
    });

    it('a whole-byte prefix compares exactly those bytes', () => {
        expect(within('10.20.255.255', '10.20.0.0/16')).toBe(true);
        expect(within('10.21.0.0', '10.20.0.0/16')).toBe(false);
        expect(within('11.20.0.0', '10.20.0.0/16')).toBe(false);
    });

    it('a prefix inside a byte is exact at both edges of the block', () => {
        // 172.16.0.0/12 is 172.16.0.0 – 172.31.255.255.
        expect(within('172.15.255.255', '172.16.0.0/12')).toBe(false);
        expect(within('172.16.0.0', '172.16.0.0/12')).toBe(true);
        expect(within('172.31.255.255', '172.16.0.0/12')).toBe(true);
        expect(within('172.32.0.0', '172.16.0.0/12')).toBe(false);
        // 192.168.1.128/25 is the top half of the last byte.
        expect(within('192.168.1.127', '192.168.1.128/25')).toBe(false);
        expect(within('192.168.1.128', '192.168.1.128/25')).toBe(true);
        expect(within('192.168.1.255', '192.168.1.128/25')).toBe(true);
        // A /31 holds exactly two addresses.
        expect(within('10.0.0.2', '10.0.0.2/31')).toBe(true);
        expect(within('10.0.0.3', '10.0.0.2/31')).toBe(true);
        expect(within('10.0.0.4', '10.0.0.2/31')).toBe(false);
    });

    it('a /32 and a /128 hold one address', () => {
        expect(within('169.254.169.254', '169.254.169.254/32')).toBe(true);
        expect(within('169.254.169.253', '169.254.169.254/32')).toBe(false);
        expect(within('::1', '::1/128')).toBe(true);
        expect(within('::2', '::1/128')).toBe(false);
    });

    it('the host bits of the block\'s own address do not matter', () => {
        expect(within('10.20.30.40', '10.20.99.99/16')).toBe(true);
        expect(within('fd12::1', 'fdff::/8')).toBe(true);
        expect(within('fe12::1', 'fd00::/8')).toBe(false);
        expect(within('fc00::1', 'fc00::/7')).toBe(true);
        expect(within('fdff::1', 'fc00::/7')).toBe(true);
        expect(within('fe00::1', 'fc00::/7')).toBe(false);
    });

    it('a v4-mapped address is a v6 address: it is in no v4 block, and in the mapped v6 block', () => {
        expect(within('::ffff:10.0.0.1', '10.0.0.0/8')).toBe(false);
        expect(within('::ffff:10.0.0.1', '::ffff:10.0.0.0/104')).toBe(true);
        expect(within('::ffff:11.0.0.1', '::ffff:10.0.0.0/104')).toBe(false);
    });
});

describe('5. v4-mapped', () => {
    it.each(['::ffff:10.0.0.1', '::ffff:169.254.169.254', '::ffff:a00:1', '0:0:0:0:0:ffff:7f00:1', '[::ffff:127.0.0.1]'])('%s is', (text) => {
        expect(isV4Mapped(parseAddress(text)!)).toBe(true);
    });

    it.each([
        ['a plain v4 address', '10.0.0.1'],
        ['the loopback', '::1'],
        ['the unspecified address', '::'],
        ['a v4-compatible address', '::10.0.0.1'],
        ['only one ff byte', '::ff:10.0.0.1'],
        ['ffff one group early', '::ffff:0:10.0.0.1'],
        ['a NAT64 address', '64:ff9b::10.0.0.1'],
        ['a non-zero first byte', '100::ffff:10.0.0.1'],
        ['a non-zero tenth byte', '0:0:0:0:1:ffff:a00:1'],
        ['fffe in place of ffff', '::fffe:10.0.0.1'],
    ])('%s is not', (_label, text) => {
        const addr = parseAddress(text);
        expect(addr).not.toBeNull();
        expect(isV4Mapped(addr!)).toBe(false);
    });
});
