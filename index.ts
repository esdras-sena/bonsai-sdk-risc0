import axios, { AxiosInstance } from 'axios';

import init, { convert } from './bincode2proof'

/// HTTP header key for the API key
const API_KEY_HEADER: string = "x-api-key";
/// HTTP header for the risc0 version string
const VERSION_HEADER: string = "x-risc0-version";
/// Environment variable name for the API url
const API_URL_ENVVAR: string = "BONSAI_API_URL";
/// Environment variable name for the API key
const API_KEY_ENVVAR: string = "BONSAI_API_KEY";
/// Environment variable name for the timeout, either a number in ms or "none" for no timeout
const TIMEOUT_ENVVAR: string = "BONSAI_TIMEOUT_MS";
/// Default timeout in ms if env var is not set
const DEFAULT_TIMEOUT: number = 30000;


type SessionStatusRes = {
    // Current status: "RUNNING", "SUCCEEDED", "FAILED", "TIMED_OUT", or "ABORTED"
    status: string;
    // Final receipt download URL (present if status is "SUCCEEDED")
    receipt_url?: string;
    // Session error message (present if the session is not "RUNNING" or "SUCCEEDED")
    error_msg?: string;
    // Session proving state (e.g., "Setup", "Executor", "ProveSegments: N/M", "Planner", etc.)
    state?: string;
    // Elapsed time for the session in seconds
    elapsed_time?: number;
    // Successful session stats (if available)
    stats?: SessionStats;
}

type SessionStats = {
    /// Count of segments in this proof request
    segments: number,
    /// Total cycles run within guest
    total_cycles: number,
    /// User cycles run within guest, slightly below total overhead cycles
    cycles: number,
}

type ImageExistsOpt =
    | { kind: "Exists" }
    | { kind: "New"; data: ImgUploadRes };

type ReceiptDownload = {
    /// Pre-Signed URL that the receipt can be downloaded (GET) from
    url: string,
}

type Journal = {
    /// The raw bytes of the journal.
    bytes: Uint8Array,
}

type Receipt = {
    /// The polymorphic [InnerReceipt].
    inner: any,

    /// The public commitment written by the guest.
    ///
    /// This data is cryptographically authenticated in [Receipt::verify].
    journal: Journal,

    /// Metadata providing context on the receipt, about the proving system, SDK versions, and other
    /// information to help with interoperability. It is not cryptographically bound to the receipt,
    /// and should not be used for security-relevant decisions, such as choosing whether or not to
    /// accept a receipt based on it's stated version.
    metadata: any,
}

type Quotas = {
    /// Executor cycle limit, in millions of cycles
    exec_cycle_limit: number,
    /// Max concurrent proofs
    concurrent_proofs: number,
    /// Current cycle budget remaining
    cycle_budget: number,
    /// Lifetime cycles used
    cycle_usage: number,
    /// Dedicated Executor
    dedicated_executor: number,
    /// Dedicated GPU
    dedicated_gpu: number,
}

type CreateSessRes = {
    /// Generated UUID for the session
    uuid: string,
}

type SnarkReq = {
    /// Existing Session ID from [super::SessionId]
    session_id: string,
}

type ImgUploadRes = {
    /// Presigned URL to be supplied to a PUT request
    url: string,
}

type UploadRes = {
    /// Presigned URL to be supplied to a PUT request
    url: string,
    /// Generated UUID for this input
    uuid: string,
}

type VersionInfo = {
    /// Supported versions of the risc0-zkvm crate
    risc0_zkvm: string[],
}


type SnarkStatusRes = {
    /// Current status
    ///
    /// values: `[ RUNNING | SUCCEEDED | FAILED | TIMED_OUT | ABORTED ]`
    status: string,
    /// SNARK receipt download URL
    ///
    /// Url to download the snark (receipt `risc0::Receipt` bincode encoded)
    output?: string,
    /// Snark Error message
    ///
    /// If the SNARK status is not `RUNNING` or `SUCCEEDED`, this is the
    /// error raised from within bonsai.
    error_msg?: string,
}

class SessionId {
    uuid: string

    constructor(_uuid: string) {
        this.uuid = _uuid;
    }

    async status(client: Client): Promise<SessionStatusRes> {
        const url = `${client.url}/sessions/status/${this.uuid}`;

        const res = await client.client.get(url)

        if (!(res.status === 200)) {
            const body = await res.data;
            throw new InternalServerError(`Internal server error: ${body}`);
        }

        const json: SessionStatusRes = await res.data;
        return json;
    }

    async logs(client: Client): Promise<string> {
        const url = `${client.url}/sessions/logs/${this.uuid}`;

        const res = await client.client.get(url)

        if (!(res.status === 200)) {
            const body = await res.data;
            throw new InternalServerError(`Internal server error: ${body}`);
        }
        return res.data;
    }

    async stop(client: Client) {
        const url = `${client.url}/sessions/stop/${this.uuid}`;

        const res = await client.client.get(url)

        if (!(res.status === 200)) {
            const body = await res.data;
            throw new InternalServerError(`Internal server error: ${body}`);
        }
    }

    async execOnlyJournal(client: Client): Promise<Uint8Array> {
        const url = `${client.url}/sessions/exec_only_journal/${this.uuid}`;

        const res = await client.client.get(url)

        if (!(res.status === 200)) {
            const body = await res.data;
            throw new InternalServerError(`Internal server error: ${body}`);
        }
        const buffer = await res.data.arrayBuffer();
        return new Uint8Array(buffer);
    }
}

class SnarkId {
    uuid: string

    constructor(_uuid: string) {
        this.uuid = _uuid;
    }

    async status(client: Client): Promise<SnarkStatusRes> {
        const url = `${client.url}/snark/status/${this.uuid}`;

        const res = await client.client.get(url)

        if (!(res.status === 200)) {
            const body = await res.data;
            throw new InternalServerError(`Internal server error: ${body}`);
        }

        const json: SnarkStatusRes = await res.data;
        return json;
    }
}

class SdkErr extends Error { }

export class Client {
    url: string
    client: AxiosInstance

    constructor(_url: string, _client: AxiosInstance) {
        this.url = _url
        this.client = _client
    }

    static fromParts(url: string, key: string, risc0Version: string): Client {
        let client: AxiosInstance;
        try {
            client = constructReqClient(key, risc0Version);
        } catch (e) {
            throw new SdkErr(`Failed to construct HTTP client: ${e}`);
        }

        const normalizedUrl = url.endsWith("/") ? url.slice(0, -1) : url;
        return new Client(normalizedUrl, client);
    }

    static fromEnv(risc0Version: string): Client {

        const apiUrl = getURL();
        if (!apiUrl) {
            throw new SdkErr("Missing API URL");
        }
        // Normalize the URL by removing any trailing slash
        const normalizedUrl = apiUrl.endsWith("/") ? apiUrl.slice(0, -1) : apiUrl;

        const apiKey = getKey();
        if (!apiKey) {
            throw new SdkErr("Missing API Key");
        }

        // Construct the HTTP client using the provided function.
        const client = constructReqClient(apiKey, risc0Version);

        return new Client(normalizedUrl, client);
    }

    async getImageUploadUrl(imageId: string): Promise<ImageExistsOpt> {
        const requestUrl = `${this.url}/images/upload/${imageId}`;
        const res = await this.client.get(requestUrl);

        if (res.status === 204) {
            return { kind: "Exists" };
        }

        if (!(res.status === 200)) {
            const body = await res.data;
            throw new InternalServerError(`Internal server error: ${body}`);
        }

        const data: ImgUploadRes = await res.data.json();
        return { kind: "New", data };
    }

    async putData(url: string, body: any): Promise<void> {
        try {
            const response = await this.client.put(url, body);
            if (response.status < 200 || response.status >= 300) {
                throw new Error(`Request failed with status code ${response.status}`);
            }
        } catch (error) {
            if (axios.isAxiosError(error)) {
                const errorMessage = error.response?.data || error.message;
                throw new InternalServerError(`Internal server error: ${errorMessage}`);
            } else {
                throw new Error(`An unexpected error occurred: ${(error as Error).message}`);
            }
        }
    }

    public async uploadImg(imageId: string, buf: ArrayBuffer): Promise<boolean> {
        const resOrExists = await this.getImageUploadUrl(imageId);
        if (resOrExists.kind === "Exists") {
            return true;
        } else if (resOrExists.kind === "New") {
            await this.putData(resOrExists.data.url, buf);
            return false;
        } else {
            throw new SdkErr('Unexpected response from get_image_upload_url');
        }
    }

    async getUploadUrl(route: string): Promise<UploadRes> {

        const requestUrl = `${this.url}/${route}/upload`;
        const res = await this.client.get(requestUrl);

        if (!(res.status === 200)) {
            const body = await res.data;
            throw new InternalServerError(`Internal server error: ${body}`);
        }
        const data: UploadRes = await res.data;
        return data;
    }

    async uploadInput(encoded: string): Promise<string> {
        const fromHexString = (hexString: string) =>
            Uint8Array.from(hexString.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)));

        const jsonCompatibleArray = Array.from(fromHexString(encoded));
        jsonCompatibleArray.shift()
        const buf = new Uint8Array(jsonCompatibleArray)
        let uploadData = await this.getUploadUrl("inputs")
        await this.putData(uploadData.url, buf)
        return uploadData.uuid
    }

    async uploadReceipt(buf: ArrayBuffer): Promise<string> {
        let uploadData = await this.getUploadUrl("receipts")
        await this.putData(uploadData.url, buf)
        return uploadData.uuid
    }

    async receiptDownload(sessionId: SessionId): Promise<Uint8Array> {
        const requestUrl = `${this.url}/receipts/${sessionId.uuid}`;
        const res = await this.client.get(requestUrl, { validateStatus: () => true });

        if (res.status < 200 || res.status >= 300) {
            if (res.status === 404) {
                throw new SdkErr(`ReceiptNotFound`);
            }
            const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
            throw new InternalServerError(`Internal server error: ${body}`);
        }

        const receipt: ReceiptDownload = res.data;
        return await this.download(receipt.url);
    }

    async download(url: string): Promise<Uint8Array> {

        try {
            const res = await this.client.get(url, { responseType: 'arraybuffer' });
            return new Uint8Array(res.data);
        } catch (error) {
            throw new SdkErr(`Download failed: ${(error as Error).message}`);
        }
    }

    async imageDelete(imageId: string): Promise<void> {
        const requestUrl = `${this.url}/images/${imageId}`;
        const res = await this.client.delete(requestUrl, { validateStatus: () => true });
        if (res.status < 200 || res.status >= 300) {
            const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
            throw new InternalServerError(`Internal server error: ${body}`);
        }
    }

    async inputDelete(inputUuid: string): Promise<void> {
        const requestUrl = `${this.url}/inputs/${inputUuid}`;
        const res = await this.client.delete(requestUrl, { validateStatus: () => true });
        if (res.status < 200 || res.status >= 300) {
            const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
            throw new InternalServerError(`Internal server error: ${body}`);
        }
    }

    async createSessionWithLimit(imgId: string, inputId: string, assumptions: string[], executeOnly: boolean, execCycleLimit?: number): Promise<SessionId> {
        const requestUrl = `${this.url}/sessions/create`;

        let req = {
            img: imgId,
            input: inputId,
            assumptions: assumptions,
            execute_only: executeOnly,
            exec_cycle_limit: execCycleLimit
        }

        let res = await this.client.post(requestUrl, req)
        if (res.status < 200 || res.status >= 300) {
            const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
            throw new InternalServerError(`Internal server error: ${body}`);
        }

        let r: CreateSessRes = res.data

        return new SessionId(r.uuid)

    }

    async createSession(imgId: string, inputId: string, assumptions: string[], executeOnly: boolean): Promise<SessionId> {
        let sessionId = await this.createSessionWithLimit(imgId, inputId, assumptions, executeOnly, undefined)
        return sessionId
    }

    async createSnark(sessionId: string): Promise<SnarkId> {
        const requestUrl = `${this.url}/snark/create`;
        let req = {
            session_id: `${sessionId}`
        }

        let res = await this.client.post(requestUrl, req)

        if (res.status < 200 || res.status >= 300) {
            const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
            throw new InternalServerError(`Internal server error: ${body}`);
        }

        let r: CreateSessRes = res.data
        return new SnarkId(r.uuid)
    }

    async version(): Promise<VersionInfo> {
        const requestUrl = `${this.url}/version`;
        const res = await this.client.get(requestUrl);

        if (!(res.status === 200)) {
            const body = await res.data;
            throw new InternalServerError(`Internal server error: ${body}`);
        }

        const data: VersionInfo = await res.data.json();
        return data;
    }

    async quotas(): Promise<Quotas> {
        const requestUrl = `${this.url}/user/quotas`;
        const res = await this.client.get(requestUrl);

        if (!(res.status === 200)) {
            const body = await res.data;
            throw new InternalServerError(`Internal server error: ${body}`);
        }

        const data: Quotas = await res.data.json();
        return data;
    }

}

export async function getSealAndJournal(binArray: Uint8Array): Promise<Uint8Array[]> {
    await init()
    let proofData = convert(binArray)
    return [proofData.seal, proofData.journal]
}

function getURL(): string | undefined {
    if (process.env['REACT_APP_' + API_URL_ENVVAR] != undefined) {
        return process.env['REACT_APP_' + API_URL_ENVVAR]
    } else if (process.env['NEXT_PUBLIC_' + API_URL_ENVVAR] != undefined) {
        return process.env['NEXT_PUBLIC_' + API_URL_ENVVAR]
    } else if (process.env['GATSBY_' + API_URL_ENVVAR] != undefined) {
        return process.env['GATSBY_' + API_URL_ENVVAR]
    } else if (process.env['VUE_APP_' + API_URL_ENVVAR] != undefined) {
        return process.env['VUE_APP_' + API_URL_ENVVAR]
    } else if (process.env['VITE_' + API_URL_ENVVAR] != undefined) {
        return process.env['VITE_' + API_URL_ENVVAR]
    } else if (process.env['PUBLIC_' + API_URL_ENVVAR] != undefined) {
        return process.env['PUBLIC_' + API_URL_ENVVAR]
    } else if (process.env['NUXT_ENV_' + API_URL_ENVVAR] != undefined) {
        return process.env['NUXT_ENV_' + API_URL_ENVVAR]
    } else if (process.env[API_URL_ENVVAR] != undefined) {
        return process.env[API_URL_ENVVAR]
    }
    throw new Error("bonsai sdk env variables are not set!");
}

function getKey(): string | undefined {
    if (process.env['REACT_APP_' + API_KEY_ENVVAR] != undefined) {
        return process.env['REACT_APP_' + API_KEY_ENVVAR]
    } else if (process.env['NEXT_PUBLIC_' + API_KEY_ENVVAR] != undefined) {
        return process.env['NEXT_PUBLIC_' + API_KEY_ENVVAR]
    } else if (process.env['GATSBY_' + API_KEY_ENVVAR] != undefined) {
        return process.env['GATSBY_' + API_KEY_ENVVAR]
    } else if (process.env['VUE_APP_' + API_KEY_ENVVAR] != undefined) {
        return process.env['VUE_APP_' + API_KEY_ENVVAR]
    } else if (process.env['VITE_' + API_KEY_ENVVAR] != undefined) {
        return process.env['VITE_' + API_KEY_ENVVAR]
    } else if (process.env['PUBLIC_' + API_KEY_ENVVAR] != undefined) {
        return process.env['PUBLIC_' + API_KEY_ENVVAR]
    } else if (process.env['NUXT_ENV_' + API_KEY_ENVVAR] != undefined) {
        return process.env['NUXT_ENV_' + API_KEY_ENVVAR]
    } else if (process.env[API_KEY_ENVVAR] != undefined) {
        return process.env[API_KEY_ENVVAR]
    }
    throw new Error("bonsai sdk env variables are not set!");
}

function constructReqClient(apiKey: string, version: string): AxiosInstance {
    const headers: Record<string, string> = {};
    headers[API_KEY_HEADER] = apiKey;
    headers[VERSION_HEADER] = version;

    let timeout: number | undefined;
    const envTimeout = process.env[TIMEOUT_ENVVAR];
    if (envTimeout === "none") {
        timeout = undefined;
    } else if (envTimeout) {
        const parsed = parseInt(envTimeout, 10);
        timeout = isNaN(parsed) ? DEFAULT_TIMEOUT : parsed;
    } else {
        timeout = DEFAULT_TIMEOUT;
    }

    return axios.create({
        timeout: timeout,
        headers: headers
    });
}

class InternalServerError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "InternalServerError";
    }


}