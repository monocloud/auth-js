/* eslint-disable import/no-extraneous-dependencies */
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest';
import { freeze, reset } from 'timekeeper';
import { arrayBufferToString } from '../src/utils/internal';
import { compactVerify } from 'jose';
import { clientAuth } from '../src/client-auth';
import { ClientAuthMethod } from '../src';

vi.mock('../src/utils/internal', async importOriginal => {
  const actual = (await importOriginal()) as any;
  return {
    ...actual,
    randomBytes: vi.fn(() => 'random'),
  };
});

describe('clientAuth()', () => {
  let headers: Record<string, string>;
  let body: URLSearchParams;

  beforeEach(() => {
    headers = {};
    body = new URLSearchParams();
  });

  beforeAll(() => {
    freeze(1735689600 * 1000);
  });

  afterAll(() => {
    reset();
  });

  it('should support basic auth without secret', async () => {
    await clientAuth(
      'clientId',
      undefined,
      'client_secret_basic',
      undefined,
      headers,
      body,
      undefined
    );

    expect(headers.authorization).toBe('Basic Y2xpZW50SWQ6');
  });

  it('should support basic auth with secret', async () => {
    await clientAuth(
      'clientId',
      'secret',
      'client_secret_basic',
      undefined,
      headers,
      body,
      undefined
    );

    expect(headers.authorization).toBe('Basic Y2xpZW50SWQ6c2VjcmV0');
  });

  it('should support secret post auth without secret', async () => {
    await clientAuth(
      'clientId',
      undefined,
      'client_secret_post',
      undefined,
      headers,
      body,
      undefined
    );

    expect(body.get('client_id')).toBe('clientId');
  });

  it('should support secret post auth with secret', async () => {
    await clientAuth(
      'clientId',
      'secret',
      'client_secret_post',
      undefined,
      headers,
      body,
      undefined
    );

    expect(body.get('client_id')).toBe('clientId');
    expect(body.get('client_secret')).toBe('secret');
  });

  it('should throw an error for invalid authenticaiton method', async () => {
    try {
      await clientAuth(
        'client_id',
        undefined,
        'invalid' as ClientAuthMethod,
        'issuer',
        {},
        new URLSearchParams(),
        0
      );
      throw new Error();
    } catch (e) {
      expect((e as any).message).toBe('Invalid Client Authentication Method');
    }
  });

  [
    {
      key: 'secret',
      public_key: {
        kty: 'oct',
        kid: 'kid',
        k: 'c2VjcmV0',
        alg: 'HS256',
      },
      auth: 'client_secret_jwt',
      assertion:
        'eyJraWQiOiJraWQiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3MzU2ODk2NjAsImlhdCI6MTczNTY4OTYwMCwiYXVkIjoiaHR0cHM6Ly9pc3N1ZXIubG9jYWwiLCJuYmYiOjE3MzU2ODk2MDAsImlzcyI6ImNsaWVudF9pZCIsInN1YiI6ImNsaWVudF9pZCIsImp0aSI6InJhbmRvbSJ9.hvn_EdRZX0pAsWmOoJNUsa824Qeyzk7J3V2Mf10jBOs',
      algorithm: 'HS256',
    },
    {
      key: {
        kty: 'oct',
        kid: 'kid',
        k: 'ZbpDUmnPkvIu2-1HOS1RZrvp9O5ozsy9jMwQgHlW_OM_ldb1Sjd02xh1h6C2WaQz8jVA2J6VROQkEDTp8SPHGeEcYlrcEzpoChqAd_N80fDro01NeG391nW2NlJ-KNAseZ_OeMZ9m9p2ih4cDLj3n3P4ObBgQ4MnJtafsH4QS0LYIUrh7P-cR3YNXzrTbZIEh5H1YR7o6ZDfFna0sLL-CXeAhnGSPmabugNRV4lN6ZbyyETaUAGfFAzTtNCNsU2P47pi8YdU9N86Hr4JSpKqqjUgCfx8y02M9cBw0I2BOWZuJmWWkdBnPoxH_QEzPTuxd_juNr0e1oJXXHETFjobTQ',
        alg: 'HS256',
      },
      public_key: {
        kty: 'oct',
        kid: 'kid',
        k: 'ZbpDUmnPkvIu2-1HOS1RZrvp9O5ozsy9jMwQgHlW_OM_ldb1Sjd02xh1h6C2WaQz8jVA2J6VROQkEDTp8SPHGeEcYlrcEzpoChqAd_N80fDro01NeG391nW2NlJ-KNAseZ_OeMZ9m9p2ih4cDLj3n3P4ObBgQ4MnJtafsH4QS0LYIUrh7P-cR3YNXzrTbZIEh5H1YR7o6ZDfFna0sLL-CXeAhnGSPmabugNRV4lN6ZbyyETaUAGfFAzTtNCNsU2P47pi8YdU9N86Hr4JSpKqqjUgCfx8y02M9cBw0I2BOWZuJmWWkdBnPoxH_QEzPTuxd_juNr0e1oJXXHETFjobTQ',
        alg: 'HS256',
      },
      auth: 'client_secret_jwt',
      assertion:
        'eyJraWQiOiJraWQiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3MzU2ODk2NjAsImlhdCI6MTczNTY4OTYwMCwiYXVkIjoiaHR0cHM6Ly9pc3N1ZXIubG9jYWwiLCJuYmYiOjE3MzU2ODk2MDAsImlzcyI6ImNsaWVudF9pZCIsInN1YiI6ImNsaWVudF9pZCIsImp0aSI6InJhbmRvbSJ9.CwuiG_kexQjq3tM-6-6YxFIiSYGrYx0xMfKo225Yrms',
      algorithm: 'HS256',
    },
    {
      key: {
        kty: 'oct',
        kid: 'kid',
        k: 'g2UkZbDz-qz-xffcnzDQImoi_3zF10knL55HtNYMxd_HOIQWDIIJ1e7DObhxHuK2_Rm1jztKJNQiZiMBKzDMipUiUn05nxLatTug2wi1PeATVdRHehE1tCd4vKWXCphJq09VeM9D3z2DLUGJVVUYY1y5oREY-aJX-XuRHIMAmQgH72ogindW_1dihR0-DZXMne_YW12NE56rrLfLN8cb7vhS9SWfTn1tn06IYH8AchkBlQrv3HRrjICqkCAe454ukkQeChf8Hesk9mNlwiKDBwdbafozPRkWQYb2LIMw1SK7UzldOSfyBjjr5G_tjM6JJLdbqDCvrtqonXq0-vNmgQ',
        alg: 'HS384',
      },
      public_key: {
        kty: 'oct',
        kid: 'kid',
        k: 'g2UkZbDz-qz-xffcnzDQImoi_3zF10knL55HtNYMxd_HOIQWDIIJ1e7DObhxHuK2_Rm1jztKJNQiZiMBKzDMipUiUn05nxLatTug2wi1PeATVdRHehE1tCd4vKWXCphJq09VeM9D3z2DLUGJVVUYY1y5oREY-aJX-XuRHIMAmQgH72ogindW_1dihR0-DZXMne_YW12NE56rrLfLN8cb7vhS9SWfTn1tn06IYH8AchkBlQrv3HRrjICqkCAe454ukkQeChf8Hesk9mNlwiKDBwdbafozPRkWQYb2LIMw1SK7UzldOSfyBjjr5G_tjM6JJLdbqDCvrtqonXq0-vNmgQ',
        alg: 'HS384',
      },
      auth: 'client_secret_jwt',
      assertion:
        'eyJraWQiOiJraWQiLCJhbGciOiJIUzM4NCJ9.eyJleHAiOjE3MzU2ODk2NjAsImlhdCI6MTczNTY4OTYwMCwiYXVkIjoiaHR0cHM6Ly9pc3N1ZXIubG9jYWwiLCJuYmYiOjE3MzU2ODk2MDAsImlzcyI6ImNsaWVudF9pZCIsInN1YiI6ImNsaWVudF9pZCIsImp0aSI6InJhbmRvbSJ9.adcW5x1UulP7n1lqlsHs41UA41agYulG546jPWonNRpFbddSvS4MThofFfIVHCdv',
      algorithm: 'HS384',
    },
    {
      key: {
        kty: 'oct',
        kid: 'kid',
        k: '6tO6XgYR9J0yPrlYFO-yyUgSpXwoKbt6r3-8G53MeNj6pyWf0-juU7ca6q93r_HnNcKwnhQN95UlTM5GQXEe40HmtNBwsnyLsEgGFWVbc0AqwB1RKC-ybJIQoM94u6JIpeSiMeb7dcjcF6oSNKI7yOxAazdn7p8DQzo1W8BpwHNY4aP6og9jyMLStg_6shUG88vyVbO54m4pKQBhmEdLulnT1x1pRgqW8i9HY8CtJIxdu7ng2WqQD9u--RtFcc5PCHMRuJEXlunsvKBJ3ogYrvu4eTfUz6PpocuqGCSAthEpZqBmHFXfpsD0iUs3YqsKBOQt7jo2b5VXbjZ0NA7Tfg',
        alg: 'HS512',
      },
      public_key: {
        kty: 'oct',
        kid: 'kid',
        k: '6tO6XgYR9J0yPrlYFO-yyUgSpXwoKbt6r3-8G53MeNj6pyWf0-juU7ca6q93r_HnNcKwnhQN95UlTM5GQXEe40HmtNBwsnyLsEgGFWVbc0AqwB1RKC-ybJIQoM94u6JIpeSiMeb7dcjcF6oSNKI7yOxAazdn7p8DQzo1W8BpwHNY4aP6og9jyMLStg_6shUG88vyVbO54m4pKQBhmEdLulnT1x1pRgqW8i9HY8CtJIxdu7ng2WqQD9u--RtFcc5PCHMRuJEXlunsvKBJ3ogYrvu4eTfUz6PpocuqGCSAthEpZqBmHFXfpsD0iUs3YqsKBOQt7jo2b5VXbjZ0NA7Tfg',
        alg: 'HS512',
      },
      auth: 'client_secret_jwt',
      assertion:
        'eyJraWQiOiJraWQiLCJhbGciOiJIUzUxMiJ9.eyJleHAiOjE3MzU2ODk2NjAsImlhdCI6MTczNTY4OTYwMCwiYXVkIjoiaHR0cHM6Ly9pc3N1ZXIubG9jYWwiLCJuYmYiOjE3MzU2ODk2MDAsImlzcyI6ImNsaWVudF9pZCIsInN1YiI6ImNsaWVudF9pZCIsImp0aSI6InJhbmRvbSJ9.6PjcJqm0u97j2jeXs4xKxNMJYSzs-IpB4BSpEODH1vsg23iuei6kZ1V_pb_J7f_8MT89OxMhSXWGZ6ob3J5cnw',
      algorithm: 'HS512',
    },
    {
      key: {
        p: '5bTMNIA9KKq7Qr6twxhGwqWUDijG978xNFnBWepDe3V1w8TV3Wcbn52vpgomN6FzJarpf8zR8U4H3McyhST4kb_QOEtkH7jPp54ZylRfThGOrfThLkuCmzUcJeU6gu_99JtkiL8xexGocyZHcRNu5_vnBAn0NV1TxzMLJ_mtCB8',
        kty: 'RSA',
        q: '5Cfp-fTHpQLtyYp3o6f5YFs91SxqpIMxGnMEdDrb9kbt75ACA3UVlreLwOh0J5jxGuiDuDsXAjv9R2T0Q6_NMZcyy4RyuaN2RaiyZbl3pRueYYdekENsnNoAEvHuQP_XEZV8fcBzyxn_SROWM-lexkOYGk2BN9NpaWSnljXd2AU',
        d: 'V4_rZ3f4XZc_5Jq9-xsUuzgnlYGsd0OTkiGQjwIukGtCC7UQus8Za3aIeukCW0HSwsb2v1duGfwTCTPufBabFLiMP7QTD9aRw5PoCPuysugWfvsGywonhDJ7k36Dh5YULIU3KewcmF4AaCZIZj_tFrSikymR_TVwA_KKAmd8kqHpYLZ_A_sfQoCf8ynM4x7H2N6UQVAFCmtOQSaP2smNHVTLszTRMLVUfntMUQMu1JzLprGJ6Ge1izT21tx3sDnzqF2LuFLTQ8qzQGkhz5ZvarRyrOcO_cXCVbiM_4zkQUNqLw-dHkjSMbTTZ6yhY-K7VAS5g8WLzO-IngcN357jiQ',
        e: 'AQAB',
        kid: 'kid',
        qi: 'uCRYcqc7DcinkphNs8CXqyvcm9qRBTtpmmt3iYYs5LsqVzkhd5sPi82Si1EIuCt0mj7D4qLgqMSj8M0gCPFbbK9PJYPdtMR7Yo5Hu3M_toJRBMiHNP_PEl9q5-QrC9Zy8Iw6o0hhvUnS19Uz_4ls_e_4qY3hIz8yi4-SxCozxrE',
        dp: 'ICsztd6HshxG4VAG0Z2iuzupAlqfkq6J24T-WPM_xBhtB5-XO8xmx_GzWZNuSrgnggzvamBqvlppK3gSESdeUDsGk_uq5-5f1l-DyRwLxMkcrCvxJSSaA9ZqPLxfd1rYu9rPN39fFJcieg3QT3ujOoXCkoQ6WQba5ri1RUHoA40',
        alg: 'RS256',
        dq: 'Lk07WpKmgYJap3AGX5wTK87YeY6OBdzp9igpWz0mrpAucVOUVQdJ3lBZeEi0aeTL6V4OfTDgtn9eI0MFn0bqKYo5sLusXKgjtHdL3QEKmuND_R7vve8w95P2N-IJK_-_sb3Yidyooysfd8EV1msh5LKLB6t68c1hsxXOPNmpr9E',
        n: 'zLjWW7SP346VuI0bNH7e4NaJGQH_9CoSs4FfJBvHJR98HRtpTvzQlCtTQhbJ5BLeUJW3x_HgLRle9v6sQxSyQ9pYbPA3aq0d3-Lhmu9Bu-B8j-jRq5E5kSDii_N2AU_BC1ivafXsE6QO_1JDfvBi1yDhZPIQl5ktLJBQtJ9yymSfiZ7q-sc5ON6m9xFdVZq7t8Cu3TqCR9k7QDfRiVS9-ZinB5XAc-tW5gn5T9gB6GdOFBvXq7h0uu46SAADClw0qXIf6YHbIPJOzmBxDJvlygVDcdp_bma9finTx0bBauk_h9kp6hr_48WEphImM8r2B3Vg9d3iCgTsZ0qqTP5Qmw',
      },
      public_key: {
        kty: 'RSA',
        e: 'AQAB',
        kid: 'kid',
        alg: 'RS256',
        n: 'zLjWW7SP346VuI0bNH7e4NaJGQH_9CoSs4FfJBvHJR98HRtpTvzQlCtTQhbJ5BLeUJW3x_HgLRle9v6sQxSyQ9pYbPA3aq0d3-Lhmu9Bu-B8j-jRq5E5kSDii_N2AU_BC1ivafXsE6QO_1JDfvBi1yDhZPIQl5ktLJBQtJ9yymSfiZ7q-sc5ON6m9xFdVZq7t8Cu3TqCR9k7QDfRiVS9-ZinB5XAc-tW5gn5T9gB6GdOFBvXq7h0uu46SAADClw0qXIf6YHbIPJOzmBxDJvlygVDcdp_bma9finTx0bBauk_h9kp6hr_48WEphImM8r2B3Vg9d3iCgTsZ0qqTP5Qmw',
      },
      algorithm: 'RS256',
      auth: 'private_key_jwt',
      assertion:
        'eyJhbGciOiJSUzI1NiIsImtpZCI6ImtpZCJ9.eyJleHAiOjE3MzU2ODk2NjAsImlhdCI6MTczNTY4OTYwMCwiYXVkIjoiaHR0cHM6Ly9pc3N1ZXIubG9jYWwiLCJuYmYiOjE3MzU2ODk2MDAsImlzcyI6ImNsaWVudF9pZCIsInN1YiI6ImNsaWVudF9pZCIsImp0aSI6InJhbmRvbSJ9.o7DDJ0sPddY2sF-AqUgPBIJ7yuzTEHcBSTbwFaKs7OoJ_oy3KxksB0jUTBOJt8ci4Hdezr4EtRqzc7tTwM0-ll72fNOy8pcUCWqK7VH7AJN_MJ7Mjkh3NCSzE1ma-i10apzcjxh0urHtuBEPqC06aX36uYbbfiaJH4ST05D-V8I0lIptYn2v34AyUoBj3T50cKGRO8fhiTxE6QEh4sAQKNALJ4mGbRJA2GHKS2JHMVIoff3k8FVLjDhtGdlgUernfwe4JTYhdGtMiNOMnXLnwwrZ1XixmPgD1TqGLpEdRx2b8qmlGf-6Nw44kUeUvc-E_bP7iVB7ZoxYVCFCvibwog',
    },
    {
      key: {
        p: 'zrAvX4QVr5HoJ0htPV5DJFe3WJ69jMqP9pyz7piswDEYa7sOYT2p-r0aoqRIDmTACPoYD8coVwbarlgXae56H0phse3r0zX58sc1C9tc8VFkjOqiyYTDIWzdF_-xmlbOJ7K91Uv-00YWn3TZDkNGkWAGNqKsPMzho1BcxLQCCuE',
        kty: 'RSA',
        q: '3xie5VvVphogfTH_4uU0-f72DpkJLEwyvyU3T0iPgodkCj0TgRKJUN-JcyNhn9DTiEXJnf7L5Q6QXoBsv4LmDyM4AGasLNIznSFLsifMDVWApiZP5qlZiW7OfpKbc_yfc7yPWrBl2gCeOS9HhIWJjzXVqIkGK_YDlZoX4P9Cif8',
        d: 'Hybe9p_l--dbQlrxpx6IEfCS7pH5Y6YRCXKRDNL-epMKrOQSwXnikYujpNkBpifHROTZx-mTLYwsr2Z1cQegzkZ3FKTuGiF0kVKu0uoh0SItrYJzrWSQQHzX-2BGgN3bO09YHOE68YjpOiCcvyuksbs2U9lWv3ncdLTYSE7jdVb9U9w6RL6YuXrXrZRz0L7UVq-kFmgyofWVWQJ_bilr4q67Gjpf6pIKj04BANDp_WQysuieFIoBaY9BSC671-L97_CfWWRNV5S1F4Lgxr_fiDCOlR-HN2QSyW0lqkYcYrv7CAWFjC8ECIfa24Pl3FZCTHECDPBSDA9l3ze8zizioQ',
        e: 'AQAB',
        kid: 'kid',
        qi: 'TyAMc3jpNe1eKz-qsgYnz07ZQCAo-4HR8VYjISY8doaAHS47DiTomQf0vgacjvHsfZEI-G7f6NKbR4ti0asDZxL-GI0N9gTF06d3HabasxvXqnzsYGA5S66uVVBGb37vqk8KbvB2ch8zf7UHahOrl7DOZX6n7ry9Aw8c6fSCBEo',
        dp: 'QNQqR79aPfN56bhh6znBvYh1zaocsihm92c3WMMyjCXaDxBg9kctJaRi0ljM8RbQ1P_8xBYnpQRVWxHuZh-S1nWyJukFav4nI-svzERF5rss2rZN0P9_ZOCMiJZ-0nYfu3vo5xorF4GIXwN7gWnAnKCN0l07wOZSb7MpJdmAOoE',
        alg: 'RS384',
        dq: 'RU-35hgu-2j4mQzUrCB74gOVXJmtIOcXiQ097tLjSzFXIlsxWRNyN_8LDAt9BBLz9U2BQyXrIOHydnm9z44Sfbd6aZ18dnxj7rhudQ4qNiZPTs9uWYJZv_n-C5Lu2w0sWN_HReyx6BXzEl8fAAwg3a5jD_ZqRXQsTulN6-hCOu8',
        n: 'tB9aEo__uXjN7ouxrGno3C6XgnFblrEzsxA9PT4hH7BBOgGYeoU8PCxuRoFcWJ066G8u3ygmA81prmC1lERLy89hbUJ0DDtH_NIwE4krYdp1PIWZkcN7_IvoYU5QXScE9hvs_NtlQjUSTocPlzXO0Pw9o2mugX-wGpclCHZYSyMtcqcs_UztfCRQVSmXf8EYcarETom7C8-xSZ90DkSykYRN9_wrOCgeR0pNPzJmYbaq_RRfZHPd2G2-4LcdxMghCHwPIuK1U49ABtuREbs-rzV8u_WwQeGWMSUorY6gX8p5oo-6IyQNW5LC943XWWkjexzfs0QTpMO509mBUt0_Hw',
      },
      public_key: {
        kty: 'RSA',
        e: 'AQAB',
        kid: 'kid',
        alg: 'RS384',
        n: 'tB9aEo__uXjN7ouxrGno3C6XgnFblrEzsxA9PT4hH7BBOgGYeoU8PCxuRoFcWJ066G8u3ygmA81prmC1lERLy89hbUJ0DDtH_NIwE4krYdp1PIWZkcN7_IvoYU5QXScE9hvs_NtlQjUSTocPlzXO0Pw9o2mugX-wGpclCHZYSyMtcqcs_UztfCRQVSmXf8EYcarETom7C8-xSZ90DkSykYRN9_wrOCgeR0pNPzJmYbaq_RRfZHPd2G2-4LcdxMghCHwPIuK1U49ABtuREbs-rzV8u_WwQeGWMSUorY6gX8p5oo-6IyQNW5LC943XWWkjexzfs0QTpMO509mBUt0_Hw',
      },
      algorithm: 'RS384',
      auth: 'private_key_jwt',
      assertion:
        'eyJhbGciOiJSUzM4NCIsImtpZCI6ImtpZCJ9.eyJleHAiOjE3MzU2ODk2NjAsImlhdCI6MTczNTY4OTYwMCwiYXVkIjoiaHR0cHM6Ly9pc3N1ZXIubG9jYWwiLCJuYmYiOjE3MzU2ODk2MDAsImlzcyI6ImNsaWVudF9pZCIsInN1YiI6ImNsaWVudF9pZCIsImp0aSI6InJhbmRvbSJ9.U_ySJA45QZswuTBsvxVll-lsYqkOz83oOm72Y1WrOJA442Ol-shVyFgPpWcofHc8BGUPVVaOZ2wuFkJSsKVwGKzsW726QsSAnomCNZYEEUhzi95wBjNEhQbcZeiLJ0j7JFFtE6ron-4QMJVYPaNPNodzF6fJm7SiG4CuK5_TEjNNnEmjwEEl19085lgja_Ev9uyh6_nM10M0S1zSm3ii85MQm3xzGWZ5iU61rarUDH6Np9gpJnIWTBDPc2gJzg6-dA9A-ko590Cu5pla6Gn95v3wtxV0T-1uF1H7-MNXiZ9xnkMOmCMw9tjxbSKRLzzC9vf2QvwPeZuhKAgfkLzVtg',
    },
    {
      key: {
        p: '2ORG5OxFEpicdYjNd6pMaPf-2cKwn86O3izn__lwzJHL_2VStmO8VmKc46n0aMGumwo-wdSytF-b-6htbUHvIX-HGYv4vdLenaGI1pGAUVXwLTrYPPO3UAEiltEAVpqcCglh-TTg_HDv3E-j6e1nBKTqRweBP5yhweFR7q5DyWk',
        kty: 'RSA',
        q: '88qlNAstkBUdYTlWST6cHAEKcLW8VlRXqdjeb6_4RkKj5LHeA21C1Gsx0zrHEOs4mU1cJHlmTjog1mTPFtUcTWepcbycDO5-yuaI78F-oj5mFBfOki0ppVuOYrAEthpur6XvFOgloupASdJ9sIQI7l8p33awTkzjYUQfgf5kNT0',
        d: 'H0lF_X0hQb6L1KYGmFuC6q5qFivtXe7MiBOv-LpJR9ETTc1N9aZnxRdpa_zlfIQMy-huPS-n-_gBrhsCNd1jh7HZDwyHh4V-diBQdfTYyxUFcng-XGrUM_nPrjGE8-uLLIn6hcxrscVdnYk_Jdq6c-OIEFuPK0NEZOh1_9ZClIYedTaRjwphzfNnYXjjuE9B9fXeieVnXuLY22v9Iq7u4CPlV_uN5EuuQDeCZAlaEVU0U5ztbuR9ICP7kFVAqEu1gSFUX6ckYD1LHXaiNTgx-mIF9vhR9u-mjBNgt_MFBUMlcVOBhXTN93cXYsQ74jFmMI5eztCKy0PhzKeyYBquoQ',
        e: 'AQAB',
        kid: 'kid',
        qi: 'yHp6Z20te59SyB16EbVq3zfofd9X0n9lmgdV0uUM0juXRyPGFU5uvJp7470v3CRPwLV9Rti3BgjZw22yO7JV-R9w4rrLqs1aE9nQMfh9rIS_tjf3mbKKpZsq1VwJvY_wSN9FiVUmPrwASEzzKg-YK2B-A8B91oD0f0NcDHMLRho',
        dp: 'KFooOnUe0Lvl-BQQrh_YAXuKRbdsJv9GI13VeBFPhC_n9UdDoT1jD-te5xh6qXbHZn78eBF7ggV7vtFyMm6e7-uLFhytlZuC4W7pR4pghkFn4vJcwtJRG6hqaAbQekxflZpzSOsmpLDaX3HNvDr3_Kw2Dir-R_h7O9gQ50gywmk',
        alg: 'RS512',
        dq: 'yhSL5Bvv5KLb-58_eu8_D6d9M_gw6Y54K_3sQ8AlmHfcytD1KvoCj3lbj7AFGm0gOVL6sfE_cFCWr6BYWKDGGRN4TSL-Z2m6CA4YLETD51C55KXnQRvWjY7a88rb3OcEIOz2xOm5aNWr_IVSUmLf1FdlqioD8qOhRxrk0yg_gDE',
        n: 'zoxfYnZwWy6j1noqTXh9YzCupzYeHfhg71IV09tuti1qjcys24TfNcyKNaXUqRt_ksrn4Msjcv1Vsn-OjeBraQT_HtugsBvMnriOTntJhT49nuzPJfcX3_iq0k7xDdxwv5W6auQO6RoBKG6zaVeB6U5RVVLYb6ykvWk2tF6nVZ3ENSAA3sruMfk1jYNHOFx_BXY7vUDEbI6wnsXbf_HX1ATA1byzhSsSqdo7TfEXfcuGXrQR9b7AcbDzRm4UrFEH0sLT-uuYlMtTttEqqZpvGCQHUyy5zuNRUODbrOeSqJ3DKUsyf-gMa_Oyi_TaBazsLk77lgfsCMr5Onktad27BQ',
      },
      public_key: {
        kty: 'RSA',
        e: 'AQAB',
        kid: 'kid',
        alg: 'RS512',
        n: 'zoxfYnZwWy6j1noqTXh9YzCupzYeHfhg71IV09tuti1qjcys24TfNcyKNaXUqRt_ksrn4Msjcv1Vsn-OjeBraQT_HtugsBvMnriOTntJhT49nuzPJfcX3_iq0k7xDdxwv5W6auQO6RoBKG6zaVeB6U5RVVLYb6ykvWk2tF6nVZ3ENSAA3sruMfk1jYNHOFx_BXY7vUDEbI6wnsXbf_HX1ATA1byzhSsSqdo7TfEXfcuGXrQR9b7AcbDzRm4UrFEH0sLT-uuYlMtTttEqqZpvGCQHUyy5zuNRUODbrOeSqJ3DKUsyf-gMa_Oyi_TaBazsLk77lgfsCMr5Onktad27BQ',
      },
      auth: 'private_key_jwt',
      algorithm: 'RS512',
      assertion:
        'eyJhbGciOiJSUzUxMiIsImtpZCI6ImtpZCJ9.eyJleHAiOjE3MzU2ODk2NjAsImlhdCI6MTczNTY4OTYwMCwiYXVkIjoiaHR0cHM6Ly9pc3N1ZXIubG9jYWwiLCJuYmYiOjE3MzU2ODk2MDAsImlzcyI6ImNsaWVudF9pZCIsInN1YiI6ImNsaWVudF9pZCIsImp0aSI6InJhbmRvbSJ9.jp6JZYn1jZ6b4jKxQcUFu-A2467EdEPNRDi6f99NUW6iOW-tDukwkhaLGH8Ml3x5Gq2qjX6f3G2XUb0JHwhD3OIXuZAxYnHUZkcXTouGykRl_YFoDX0lAp1-_d2MNvP3e2zHraAAi0Z96byINnflvipY3xN-HItc7i1AJ7paSGT21l4Mwpntxf6zQDHPoyuue5uetlryFCoxzHCC8Vw9YgTHg3wpaMOgWHPSMkTvvkB4Wr8ZfHRG8P75SAj6TJ4HVdFJdUX6crBlt63tlgjh-_DDDSByqQEQOaq3C-jt2t38IZ95q_PgivwbMRL75rTntRSdFmO6aIujinZG7xNiPw',
    },
    {
      key: {
        p: 'z2mekVBpmI9FSH-d6qYKVmjKYo7E-vaetrXV8lXS-tPaHCsKWaobPocUMwoKfW_CwrMBosO-YMWhCWV2afOADRSmBLqhjKXhfoOEERM2UlA_yN2WtMcCF8Tm-QdDNHef3Jn8NlgFCNVW0AnDhmrqjrRGhSJWWYA4kvKIW4NCs1k',
        kty: 'RSA',
        q: '4y_ADblj_kxHm3oz1c15rfXkWmqgUVnqNVKlBndlNfpI-5XT7QQ7NLhn1T6qlPtSP3LFrmZucJdZro9KRC0T1ZVAJu2-u2FYNlOJxgKwWQFs8PCZGMNuHkZVhokczy-awfMgydWI8qxGQS21EmnOfGlCUrwxyJYz9NKJI2EISPc',
        d: 'KuRDpOHIuLdTMFjAC3thsRQUTaPOIYmQRUDckPmnNhcxr59yHbJXlQUnKSbEYu3SWyq4d-cIodhJJCyZIIHgqZO__vYofoEms2SVnZ7UDYTF8-5IOqz5uhQHrPVEnDzdxExJw9yxx1Tyd3IvnQdj8K1cZgN3s6omt6vog34iLrsgHFe7ZIGi2lzDLL3DxFe0F8Ln45x4KyKu__caZhWWHoarJz9BKnYhTxP-Md-HdRULlC7BLzr23LDXZysPlCLo6KuS7RZhTNEyQWED1MwCvYCPWOWIu6fuyIRv0nQ9FqdRQmD0Dvq5rQh3pjWQNyb-4ZOUyNcmKOoCq7bIQUxzOQ',
        e: 'AQAB',
        kid: 'kid',
        qi: 'WrxIuIe3C3QwncrzfTu--5KCUtFGrA3Zzk2C_i9CxLDLsUw8uSTURV6OUAXjHIK_ki2xk-SECbbM_3e3dKrkCAohyrhwccYU2ppcx6t8YXfsblK_6EFYCcFt58TCh2d4zeu4PZOP3WBHnV9n1Eb1qo91FKIvvGfKRp05sL00-Vg',
        dp: 'P7X-2j4sIYuoyYtB08krFb3cpQeb5EcLG66hSG4qf5fBwLNL250P_1X403C7JirFVY8s6nVcLlemjr9W71a3t8zm7j7xzsVJjdYSJDiVkBVMcoP2fhM_RlPaaxZbA2vXdCjsuziwWzVFFGRbZhfDcxBXNSAGDDoBpsnPLuUUAQk',
        alg: 'PS256',
        dq: 'tP-U_homnTI-lpMcewkSGVNfE94BTe7Z1pO6YFV9MCzwOmhbCGknllAYgV9E3h8AnwYckl6PPGqIi7cjTv-u3qnjC2C8ZWMfuWCC0lvQDYlCNw8omf8RW1NjziSs7DAcFstR4xuZ2OUBr-nvafUcCih-K5Y9_3YTfMjDc4lZ5W8',
        n: 'uBFXmUx5xtJChyCnKsMGziJFPomBTyA1Fg3kyl6htfaovF7xU38_AsDMFLfaAmaP9m3xrYiA9SlDNAU36mRqK1cE7pPCSe_PZUv2e15DPkOhgCaO46X88zJ6eNyynvUHTZs8tewpva4TGZVR1Vq2vMJfBTgxq_aedcW3n3zwgAhiL2xYjYVUNPesTh7nntCOlzVOxdrOB8ek293fbwBbDO29BVg4Cru62w-Yb_ZUFPGzBT0CdgXckEuLTquN4u49dpHaXfX1Y4HObjAMku1Xc-S-_i-yM_42KzUgzs-Q6C9cgd5jjslG0_LbMzd-4pKjrc6NB0YT202FDtNru5QS3w',
      },
      public_key: {
        kty: 'RSA',
        e: 'AQAB',
        kid: 'kid',
        alg: 'PS256',
        n: 'uBFXmUx5xtJChyCnKsMGziJFPomBTyA1Fg3kyl6htfaovF7xU38_AsDMFLfaAmaP9m3xrYiA9SlDNAU36mRqK1cE7pPCSe_PZUv2e15DPkOhgCaO46X88zJ6eNyynvUHTZs8tewpva4TGZVR1Vq2vMJfBTgxq_aedcW3n3zwgAhiL2xYjYVUNPesTh7nntCOlzVOxdrOB8ek293fbwBbDO29BVg4Cru62w-Yb_ZUFPGzBT0CdgXckEuLTquN4u49dpHaXfX1Y4HObjAMku1Xc-S-_i-yM_42KzUgzs-Q6C9cgd5jjslG0_LbMzd-4pKjrc6NB0YT202FDtNru5QS3w',
      },
      auth: 'private_key_jwt',
      assertion:
        'eyJhbGciOiJQUzI1NiIsImtpZCI6ImtpZCJ9.eyJleHAiOjE3MzU2ODk2NjAsImlhdCI6MTczNTY4OTYwMCwiYXVkIjoiaHR0cHM6Ly9pc3N1ZXIubG9jYWwiLCJuYmYiOjE3MzU2ODk2MDAsImlzcyI6ImNsaWVudF9pZCIsInN1YiI6ImNsaWVudF9pZCIsImp0aSI6InJhbmRvbSJ9.Qc0c-JgsbW2spacn7WZm5xiU3R0Y_c0WLhF0xjiscWTrpkpNreUlFBzIH7is440ax_oLYruKSbHJT3ac2YIkEflpAafA8v-s3qlCv8vK3Ts32LbWVIIACnyc96qglEPLX0J2RU5kWIvXfZPJWAsgTQIRWSOveSg0ovPTE0OKeMAEEnda9oe5ZT8x2VAr2LTrCcteTJX2S1kBiag16G7X1LDW1MYyLlFB4aCzJHJ-CkfYlZZMB-SRsIkRJxcLkLStIAXuAC0D15vsIOR3baFMA-E-GonGbGVLy20VAVhRbisqxyPIOV9J_jRNnRbG_Q6ZF1Wynxf-5IJkl2DV2gmgAw',
      algorithm: 'PS256',
    },
    {
      key: {
        p: '6G39-U6pPJuvt2j0HnqysFd1xfRivxdnpVzUSiDaLxg-VEHwLdMRnVbxFYWwjtMTu9jE-1k5qgiggG6jnmKoy8rFZWoeCBms2MkUkG-KqrQ3mp1j-QUD5bZLX3-W-iBvhlgdcpna_SHvUoQN7TrL1AGRN_rgXokICJWB-G1JVws',
        kty: 'RSA',
        q: 'xYDPIUdBEkMxwusFggdzDnbNcUjKWelZIDDcxG9e_1SWaL7MShDnXgHJYIfnVVwEfk0S7SlCaAnF9BAWOn25If7Dgsi-_y30BOrImfMgoCPt_XB8eCqGzDYd1mXNGtXt1xQJRkEB31BlsUOo8cmS5vV6STc29_JD1_gtJHQR4Zs',
        d: 'NbrL7wQWERsimbT7uZIL1ouGfW6i9g8Wgy_n7sdjuWoEB1IULYnV5mdPZ1C3g3SfR7gAMwv1G0AVEnLh847eedo9OnPn2LdzROYAbR4tFfvVPVoyjSDzKB-ikoZL7HJ-9s50ILFTCXClY6I0RTRFXRgJVd6-cZawZDcLJUrZGv2HH-GlLAdNdoTDXz24q4pM-k2pUkzMVRYuC7wZ-Ac37BtNwR67Jhv8k4AlknRtoJMTzPuzLmrRcc4gGcC8SEbsyBHOfxQYXW75ZDsTXfaidWGcSz2Wr4cES3iQH10F3X8k7jDOoObBUzKU4l7amIGUKc9FvFadhZPOlv0NLHcQ1Q',
        e: 'AQAB',
        kid: 'kid',
        qi: 'uwyhUdProqElezGXvyQ6vHWRDbg4nyfc1r_UTi1SM9UAO-9XwHHr8E3z0bEtPlGKUxh0qr5Yq0m7kylkkfRn-Gj8inzHzVYi4q-ui8-A62L-mFAaAUXKR_pJVP2gx1DfyzMOi5f_1PDSlrIO7KK3mm3a-W-u3fPcqW6AQkU8ocU',
        dp: 'Y1E8yR8XqdJMz26FgdCkMj3tEV1QJJ93pm14OQS4to8BczeJzcr3J-hStAOgYidHs2j5Iv4JaeKt0rN0LuWxgwNuPduOYZ-3ABtMMju3YSII8IR4h5vhAnNW2cPHW7IodZuJWcLslGW_wd6zpL8PAdR5nRYScdLUH_bixqjMQek',
        alg: 'PS384',
        dq: 'nj0htyv7usITcHQUqaWGTaRp3cXQOlF3kw8TEl-Y4UHIcIvN6dm5Rdxwl-LLOdzLzNW7wEA6cFjEPVNWO-7XEaGoy3RDcvhCdl4V8yKUlTm0SEaDs1N_RMZnCYvu1P1p3dSzyZH0ChPEJk5rYa17AYjUPSz74ZQ9PyAcKwTD_tk',
        n: 's1GXfv1refJ206GHfytQHiHh8zZ1hWeBUFL0G0OF74SxQ2M9v9wrBiFEVULSzebtWVtLWi0if2Iaz2l1WSsIyHXWyYjmwZWlqSqo-Bg5hQZJXASjyIJ5YocsNZDUYEs9WrAptL7aPi42ayEtS2XWHjy0PjY12HYwj2U4kfvit7oOyYNymsVlEdSv__SRT6Sp3R6d-uL0IkbeN7eSQs0lcnc85chmfAvk01-LdDsIWPo4xEitVonIhwUpXQmHBQ6m14ffGP5REuz_YPu0gkUXPuBTgXiKEvmEVz6CpEMM0j2I-27qn_s58dDgb-92cSmxbWJL6PKB72efCrNTZKNeqQ',
      },
      public_key: {
        kty: 'RSA',
        e: 'AQAB',
        kid: 'kid',
        alg: 'PS384',
        n: 's1GXfv1refJ206GHfytQHiHh8zZ1hWeBUFL0G0OF74SxQ2M9v9wrBiFEVULSzebtWVtLWi0if2Iaz2l1WSsIyHXWyYjmwZWlqSqo-Bg5hQZJXASjyIJ5YocsNZDUYEs9WrAptL7aPi42ayEtS2XWHjy0PjY12HYwj2U4kfvit7oOyYNymsVlEdSv__SRT6Sp3R6d-uL0IkbeN7eSQs0lcnc85chmfAvk01-LdDsIWPo4xEitVonIhwUpXQmHBQ6m14ffGP5REuz_YPu0gkUXPuBTgXiKEvmEVz6CpEMM0j2I-27qn_s58dDgb-92cSmxbWJL6PKB72efCrNTZKNeqQ',
      },
      auth: 'private_key_jwt',
      assertion:
        'eyJhbGciOiJQUzM4NCIsImtpZCI6ImtpZCJ9.eyJleHAiOjE3MzU2ODk2NjAsImlhdCI6MTczNTY4OTYwMCwiYXVkIjoiaHR0cHM6Ly9pc3N1ZXIubG9jYWwiLCJuYmYiOjE3MzU2ODk2MDAsImlzcyI6ImNsaWVudF9pZCIsInN1YiI6ImNsaWVudF9pZCIsImp0aSI6InJhbmRvbSJ9.qslZg5yOdJcgtxDhD6rRPTLaibcpj5VxKdRMP5XTp3uTJR-9ULiDcura50gQka_eQlFxvXncxQHxnk5lDRcFDwFP-3gkcFw0q7f8ugKp-qaHxsKKDbekzEDBkTp7MTUXgYnadn9tvO8erRq4_i9CYzyqBsdR7yO8TRZbHvCgE564cI7OpzVOUFL7OYzTuJP3AJQcCFlqmIklHLDnKFZM28NQpqBVvyYPS_c7H0Vk4mKELdZmewgbpcnPZFASe6PaUb2HMgKy_xrq-BVUVD68FQ5DB8Bljmm6y4xcBzIgTtp_XPcBFdD1-T42lW53RpoaUe5u4EEbpUMxR8kKa932xA',
      algorithm: 'PS384',
    },
    {
      key: {
        p: 'vS_9CqwIxA4iey5tY2KvrdoMDJQh0-H8NOJGTFGYy5eSV8BdLCsIDPp4JlTLu4yREaan8LJnwCK4Q02cjr7rBUqDPtw4DrGsYLcTzjiYKFEdlssx_7s-EWZLSszh4o-0DM_7rnaeghxk3BFwfwQT1FlHSQLT9l64t5bIzC_6BYU',
        kty: 'RSA',
        q: '7erniKQzu1tGzvlKrYaamQXshLAgWzR0K4xvq9h65rlt4Tac9QhGfYNcmIvAqwpj2XMbdX-PdPUcmo3Jswwc6Km54PVPMn0rylfGSTTxCRSBr2mHLJ3gQ8AmS7VcrI7T2bVnjpcslLNr-xBXFPuPo2g-yoEjLnjb3djTqNofoBM',
        d: 'ASXzqHe_dtZOJBzHMFrZRPboBk8uMfajnmngWxLvrpmwxZBOkkLTY57IlBsTBsBUW53yjbQUMYgC47XuQYoNpJrUtgSJEKzKaYFEVtdoYbh4tlXyQ4SE_aYWI5_O6aVtSN9jV_x0QO4458FbotsXbr0Oyg69d5KxYCvcCg93me1P3qugDSDAHS20DZQ6XrauX0QdroLv-l9HJbWZIvsLVClsl9qCM6DVhXgzgnbWcPV1Gr7m6MRw5Z-UCx3VrNrkp3kkht-YkbD6pTiRTZGztFLCyP3zlPZSrKJ7uOIU-FB3p0cg4luBljKSxBY1TM9Q7EA0jKCcLLFks2n9UHL8YQ',
        e: 'AQAB',
        kid: 'kid',
        qi: 'VAmdn859UcYXek_5J2ljZe5zX_3W_yYZnOXvYaoWf0KUomzdUChPTN0xJtDSSzlGolq7RjTDmCKYAL7T8QoFMmh8SLpSCODJHlZA1cI0p7HSKRqbyolS8yDP4E-JLIpbKsrcLWiE5wyL0DcNvIWeoGXWQ5ducPVl7wDLLfE1wUY',
        dp: 'pjWH4R1dIims333deqhT4bAkT9TAl2797dQxoJE7ZPqIBnIpKUmw6_4NGtf6mY4YUWKSPuPuRJ38Npz0A3D195MMFWjSEw7De8C8NLwB6cHB9h4UkjEFibHOSiwP88T-kRcUbaUnAvZBIhpsNBr39OJuv1UttVBohlqBlOo9hSU',
        alg: 'PS512',
        dq: 'VfYcx9sEMfqNv_SEjePncciZJ2v3lNyD6MQqCP4Dkd-Hmuq_lSzzQyA2UYuVBnePkh6r2i1HqOty9UiriryiqVHBrk0T21ssekRyiTrOqAg3vygyxeUZBYGklJAnttU4KB4KF5P5cJTPO_wwao1l3ZWpskMscfsK_cH837JH4O8',
        n: 'r9MGO3UxZYtZ-C0KP2yilHEKTBXVnmfTK_WxnXuqycr9KVFtMxQgkNnWqalZnYVyzyLLJ9rarsbUxK1wIa4qQ0YrkrB_hxdhEvK_d3mN1XHnXIGOCNehmJHRLDrwH05QVCQEaSZsfeRjRrylNkRcAq-Rai-Q71kXPvHFVdXtsZl42f4g7DrZFsKMt3BChW7QadU_GZA71WVSqvhFEkKJKyu9UVsPVp4uj5vpJPFtpUBSGcRjmtkZnhjarxCZiGFbCHQnAXPH7ywboFM6M4UrbkY3s_e423Q-_naWITrh5fhUbLvb2WQtXRIDydbDQv9riMcnJ1m3kL4XHXtlwByI3w',
      },
      public_key: {
        kty: 'RSA',
        e: 'AQAB',
        kid: 'kid',
        alg: 'PS512',
        n: 'r9MGO3UxZYtZ-C0KP2yilHEKTBXVnmfTK_WxnXuqycr9KVFtMxQgkNnWqalZnYVyzyLLJ9rarsbUxK1wIa4qQ0YrkrB_hxdhEvK_d3mN1XHnXIGOCNehmJHRLDrwH05QVCQEaSZsfeRjRrylNkRcAq-Rai-Q71kXPvHFVdXtsZl42f4g7DrZFsKMt3BChW7QadU_GZA71WVSqvhFEkKJKyu9UVsPVp4uj5vpJPFtpUBSGcRjmtkZnhjarxCZiGFbCHQnAXPH7ywboFM6M4UrbkY3s_e423Q-_naWITrh5fhUbLvb2WQtXRIDydbDQv9riMcnJ1m3kL4XHXtlwByI3w',
      },
      auth: 'private_key_jwt',
      assertion:
        'eyJhbGciOiJQUzUxMiIsImtpZCI6ImtpZCJ9.eyJleHAiOjE3MzU2ODk2NjAsImlhdCI6MTczNTY4OTYwMCwiYXVkIjoiaHR0cHM6Ly9pc3N1ZXIubG9jYWwiLCJuYmYiOjE3MzU2ODk2MDAsImlzcyI6ImNsaWVudF9pZCIsInN1YiI6ImNsaWVudF9pZCIsImp0aSI6InJhbmRvbSJ9.bEAm3S0p9QeJ7j5eeWJIxmp1WVlv9Iu97bgfyZpWjBSMCBZm9FxuMOf7utbwcLJIJQFqrWl_us5VzSX0oNj5-RNCRYM-j3ZtCuOMCYdjvDVTRkLkwdPSbFZYeJfuetYUbIubgQAwejHJxGXQAE1fj4_fTM2f_c3CF1lI1zmTHzrcbKdIRsKRwiVG-0MdKIeyFTEMGklncNlYEIsf4BKJ2XDjuH-mdQaPD8i2IDu7gdZ8P2xK8L70z5XFrgSrH5sEokJKGBjPzHb4CfC4e_z2Iv6SxObtogIgpOeniyk70spH4Y0S7XwV3ecbtbQ0crw53UrE8RQZ-98UVjCTuzRpYg',
      algorithm: 'PS512',
    },
    {
      key: {
        kty: 'EC',
        d: '85_aY9PPcyWBsrmLoGkmQ-1KCoKo6pqVm62OjBiBz5A',
        crv: 'P-256',
        kid: 'kid',
        x: '18L8cT9bBsQHs2o5wmgl-7DvfQhXNw4UbINWancRbsQ',
        y: 'gSYg5kdTCirpRXdM0_RpNm53r45wSo9nWmAK72b_dGs',
        alg: 'ES256',
      },
      public_key: {
        kty: 'EC',
        crv: 'P-256',
        kid: 'kid',
        x: '18L8cT9bBsQHs2o5wmgl-7DvfQhXNw4UbINWancRbsQ',
        y: 'gSYg5kdTCirpRXdM0_RpNm53r45wSo9nWmAK72b_dGs',
        alg: 'ES256',
      },
      auth: 'private_key_jwt',
      assertion:
        'eyJhbGciOiJFUzI1NiIsImtpZCI6ImtpZCJ9.eyJleHAiOjE3MzU2ODk2NjAsImlhdCI6MTczNTY4OTYwMCwiYXVkIjoiaHR0cHM6Ly9pc3N1ZXIubG9jYWwiLCJuYmYiOjE3MzU2ODk2MDAsImlzcyI6ImNsaWVudF9pZCIsInN1YiI6ImNsaWVudF9pZCIsImp0aSI6InJhbmRvbSJ9.xTQzOp2PvttNyAJXZU3C4XCK5TwljAEb5j4tug8tfj30fX0m1BlEwHlpD-evPFjqWw_PGRqr0t6BLzs3Bpmf-A',
      algorithm: 'ES256',
    },
    {
      key: {
        kty: 'EC',
        d: '5rzIzoENxMmNmpwbsxjqIzukBnSH41XNwf6-zD3cxy_K7Uv5hFo3Dly1jO3tHOPM',
        crv: 'P-384',
        kid: 'kid',
        x: 'lV1Bh6N1ibaLNdZWivqQZE7MBTCf-EbHxnJ9UFWvO5qE3nAT9wv_JdlhnlsSiZxj',
        y: 'xCmZWTHwveLnW7EKMuP9A3KpTfHsf1LswrxGS1lnEUr-iqqqQGVvzaTVG9tnGAKy',
        alg: 'ES384',
      },
      public_key: {
        kty: 'EC',
        crv: 'P-384',
        kid: 'kid',
        x: 'lV1Bh6N1ibaLNdZWivqQZE7MBTCf-EbHxnJ9UFWvO5qE3nAT9wv_JdlhnlsSiZxj',
        y: 'xCmZWTHwveLnW7EKMuP9A3KpTfHsf1LswrxGS1lnEUr-iqqqQGVvzaTVG9tnGAKy',
        alg: 'ES384',
      },
      auth: 'private_key_jwt',
      assertion:
        'eyJhbGciOiJFUzM4NCIsImtpZCI6ImtpZCJ9.eyJleHAiOjE3MzU2ODk2NjAsImlhdCI6MTczNTY4OTYwMCwiYXVkIjoiaHR0cHM6Ly9pc3N1ZXIubG9jYWwiLCJuYmYiOjE3MzU2ODk2MDAsImlzcyI6ImNsaWVudF9pZCIsInN1YiI6ImNsaWVudF9pZCIsImp0aSI6InJhbmRvbSJ9.T_EKMR4oAH-WNAsVd9PmgixjFvzaocnXqJW5vEb7cO7DpXEeeCZBocIw90LW8IL8_cHJJCfHRJvU0uF2H16iCdNV14x5RylagxiXkl-3a5JtLrPAcrB76UcAL6QegPAr',
      algorithm: 'ES384',
    },
    {
      key: {
        kty: 'EC',
        d: 'AX86UjOedecenB5dT7hkA2YfeYz5HNTFmdP17itqfProhRva50vqAwyLSNNAFuAnmn0Pmbq7F-R6oowkkAffqgRL',
        crv: 'P-521',
        kid: 'kid',
        x: 'AdbGJRa22j9Af2H7UZgi-sbCLyNn65rXq9oSA-_WqHUvgMTYMIYOz_zRE8KqlSI-GWv5TCWB0sxUp5skXU48-ujA',
        y: 'AFOdPGxuQLTU7sgdIv7thpDd-YXxRrws1cPqCTCvNCcrKpDhxxELHoMDgCqIY4cjap-4mh2FeDiJhETHJTqZo29d',
        alg: 'ES512',
      },
      public_key: {
        kty: 'EC',
        crv: 'P-521',
        kid: 'kid',
        x: 'AdbGJRa22j9Af2H7UZgi-sbCLyNn65rXq9oSA-_WqHUvgMTYMIYOz_zRE8KqlSI-GWv5TCWB0sxUp5skXU48-ujA',
        y: 'AFOdPGxuQLTU7sgdIv7thpDd-YXxRrws1cPqCTCvNCcrKpDhxxELHoMDgCqIY4cjap-4mh2FeDiJhETHJTqZo29d',
        alg: 'ES512',
      },
      auth: 'private_key_jwt',
      assertion:
        'eyJhbGciOiJFUzUxMiIsImtpZCI6ImtpZCJ9.eyJleHAiOjE3MzU2ODk2NjAsImlhdCI6MTczNTY4OTYwMCwiYXVkIjoiaHR0cHM6Ly9pc3N1ZXIubG9jYWwiLCJuYmYiOjE3MzU2ODk2MDAsImlzcyI6ImNsaWVudF9pZCIsInN1YiI6ImNsaWVudF9pZCIsImp0aSI6InJhbmRvbSJ9.AUL7SnXFs4gm0XzFVI2Aj1IP7fStwo0K3Dqr62uSqD3RFDVCPUP0gKSTfJ5ieJMwpY5WdIrxRNk7WglQKJ7sZ5OjAFGSGSqVMCyXHPlNKrCHJmzufCmmKJMTCmmrrESHkttshCzxJ_ivJw-tfg8ju3rrjoT5uWivjK4rYN2iFZRptUp8',
      algorithm: 'ES512',
    },
  ].forEach(k => {
    it(`should support ${k.auth} - ${k.algorithm} `, async () => {
      await clientAuth(
        'client_id',
        k.key,
        k.auth as ClientAuthMethod,
        'https://issuer.local',
        headers,
        body,
        undefined
      );

      expect(body.get('client_id')).toBe('client_id');
      expect(body.get('client_assertion_type')).toBe(
        'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      );

      const assertion = body.get('client_assertion') ?? '';

      const verifyResult = await compactVerify(assertion, k.public_key);

      expect(
        JSON.parse(
          arrayBufferToString(verifyResult.payload as unknown as ArrayBuffer)
        )
      ).toEqual({
        exp: 1735689660,
        iat: 1735689600,
        aud: 'https://issuer.local',
        nbf: 1735689600,
        iss: 'client_id',
        sub: 'client_id',
        jti: 'random',
      });
    });
  });
});
