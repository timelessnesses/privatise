/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.jsonc`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

import { fileTypeFromBuffer } from "file-type";

const corsHeaders = {
	'Access-Control-Allow-Origin': '*',
	'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
	'Access-Control-Allow-Headers': 'Content-Type'
};

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const url = new URL(request.url);
		switch (url.pathname) {
			case '/upload':
				if (request.method == 'OPTIONS') {
					return new Response(null, { headers: corsHeaders });
				}
				if (request.method == 'POST') {
					return await upload(request, env, ctx);
				}
				return new Response('Method not allowed', { status: 405 });
			case '/upload_encrypt_serverside':
				if (request.method == 'OPTIONS') {
					return new Response(null, { headers: corsHeaders });
				}
				if (request.method == 'POST') {
					return await upload(request, env, ctx, true);
				}
				return new Response('Method not allowed', { status: 405 });
			case '/read':
				return await read(request, env, ctx);
			case '/delete':
				return await delete_file(request, env, ctx);
			case '/info':
				return await info(request, env, ctx);
			// for user if their tiny laptop is too slow :((
			case '/read_serverside':
				return await read_server_side(request, env, ctx);
			default:
				return new Response('Not Found', { status: 404 });
		}
	},
	async scheduled(_, env, _2): Promise<void> {
		let current_time = new Date();
		let files = await env.privatise_db.prepare("SELECT * FROM files WHERE expires_at < ?")
			.bind(current_time.getTime())
			.all();
		if (files.error) {
			console.error(files.error);
			return;
		}
		if (files.results.length === 0) {
			return;
		}
		for (const file of files.results) {
			await env.privatise_storage.delete(file.id as string);
		}
		await env.privatise_db.prepare("DELETE FROM files WHERE expires_at < ?")
			.bind(current_time.getTime())
			.run();
	}
} satisfies ExportedHandler<Env>;

async function upload(request: Request, env: Env, _: ExecutionContext, handle_encryption: boolean = false): Promise<Response> {
	const form_data = await request.formData();
	const file = form_data.get('file') as File;
	const name = form_data.get('name') as string;
	console.log(Object.prototype.toString.call(file));
	const expires_at = Number(form_data.get('expires_at'));
	const original_file_ext = form_data.get('file_ext');

	if (isNaN(expires_at)) {
		return new Response('Expires at is not a number', { status: 400 });
	}

	if (expires_at < 0) {
		return new Response('Expires at is in the past', { status: 400 });
	}
	// a week
	if (expires_at > 604800) {
		return new Response('Expires is maximum 7 days', { status: 400 });
	}

	if (!original_file_ext) {
		return new Response('File extension not found (i was still considering if this should be optional and detect from mimetype instead)', { status: 400 });
	}

	if (!file) {
		return new Response('File not found', { status: 404 });
	}

	// these are hopefully encrypted with AES256GCM from client (hopefully)
	const id = random_string(10);
	let file_content = await file.bytes();

	let encryption_info: {
		key: string | null,
		nonce: string | null
	} = {
		key: null,
		nonce: null
	}

	if (handle_encryption) {
		const key = await crypto.subtle.generateKey(
			{ name: "AES-GCM", length: 256 },
			true,
			["encrypt"]
		);
		encryption_info.key = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey("raw", key as CryptoKey) as ArrayBuffer)));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		encryption_info.nonce = btoa(String.fromCharCode(...nonce));
		let encrypted = await crypto.subtle.encrypt(
			{
				name: "AES-GCM",
				iv: nonce,
			},
			key as CryptoKey,
			file_content
		);
		file_content = new Uint8Array(encrypted);
	}
	else {
		// we have rules!!! (fuck your plaintext ass)
		let [check, info] = await check_file(file_content);
		if (!check) {
			return new Response(JSON.stringify(
				info
			), { status: 400 });
		}
	}

	// 200MB limit
	if (file_content.length > 209715200) {
		return new Response('File is too large (200MB limit)', { status: 413 });
	}

	let walalalala = new Date();
	walalalala.setSeconds(walalalala.getSeconds() + expires_at);

	await env.privatise_db.prepare("INSERT INTO files (id, name, created_at, expires_at, original_file_extension) VALUES (?,?,?,?,?)")
		.bind(id, name, (new Date()).getTime(), walalalala.getTime(), original_file_ext)
		.run();

	await env.privatise_storage.put(id, file_content);
	if (!handle_encryption) {
		return new Response(JSON.stringify({
			id: id,
			expires_at: walalalala.getTime()
		}), { status: 200 });
	} else {
		return new Response(JSON.stringify({
			id: id,
			expires_at: walalalala.getTime(),
			encryption_info
		}), { status: 200 });
	}
}

// decrypt it in client because i love myself 🔥🔥🔥🔥
async function read(request: Request, env: Env, _: ExecutionContext): Promise<Response> {
	const url = new URL(request.url);
	const file_name = url.searchParams.get('file_name');
	if (!file_name) {
		return new Response('File name not found', { status: 404 });
	}
	let response = await env.privatise_db.prepare("SELECT * FROM files WHERE id = ?")
		.bind(file_name)
		.first()
	if (!response) {
		return new Response('File not found', { status: 404 });
	}
	let data = await env.privatise_storage.get(file_name);
	return new Response(await data?.blob(), { status: 200 });
}

async function delete_file(request: Request, env: Env, _: ExecutionContext): Promise<Response> {
	const url = new URL(request.url);
	const file_name = url.searchParams.get('file_name');
	// just verify if valid owner
	const key = url.searchParams.get('key');
	const nonce = url.searchParams.get('nonce');

	if (!key || !nonce || !base64_regex.test(key) || !base64_regex.test(nonce)) {
		return new Response('Key or nonce not found', { status: 404 });
	}

	if (!file_name) {
		return new Response('File name not found', { status: 404 });
	}
	let response = await env.privatise_db.prepare("SELECT * FROM files WHERE id = ?")
		.bind(file_name)
		.first()
	if (!response) {
		return new Response('File not found', { status: 404 });
	}

	let data = await env.privatise_storage.get(file_name);
	if (!data) {
		return new Response('File not found', { status: 404 });
	}

	let raw_key = Uint8Array.from(atob(key), c => c.charCodeAt(0));
	let raw_nonce = Uint8Array.from(atob(nonce), c => c.charCodeAt(0));
	const aes_key = await crypto.subtle.importKey('raw', raw_key, 'AES-GCM', false, ['decrypt']);
	try {
		await crypto.subtle.decrypt(
			{
				name: "AES-GCM",
				iv: raw_nonce,
			},
			aes_key,
			await data.arrayBuffer()
		);
		await env.privatise_storage.delete(file_name);
		await env.privatise_db.prepare("DELETE FROM files WHERE id = ?")
			.bind(file_name)
			.run();
		return new Response('File deleted', { status: 200 });
	} catch {
		return new Response('Decryption failed', { status: 400 });
	}

}

async function info(request: Request, env: Env, _: ExecutionContext): Promise<Response> {
	const url = new URL(request.url);
	const file_name = url.searchParams.get('file_name');
	if (!file_name) {
		return new Response('File name not found', { status: 404 });
	}
	let response = await env.privatise_db.prepare("SELECT * FROM files WHERE id = ?")
		.bind(file_name)
		.first()
	if (!response) {
		return new Response('File not found', { status: 404 });
	}

	return new Response(JSON.stringify(response));
}

const base64_regex = /^([0-9a-zA-Z+/]{4})*(([0-9a-zA-Z+/]{2}==)|([0-9a-zA-Z+/]{3}=))?$/;

async function read_server_side(request: Request, env: Env, _: ExecutionContext): Promise<Response> {
	const url = new URL(request.url);
	const file_name = url.searchParams.get('file_name');
	const key = url.searchParams.get('key');
	const nonce = url.searchParams.get('nonce');
	if (!key || !nonce || !base64_regex.test(key) || !base64_regex.test(nonce)) {
		return new Response('Key or nonce not found', { status: 404 });
	}
	if (!file_name) {
		return new Response('File name not found', { status: 404 });
	}
	let response = await env.privatise_db.prepare("SELECT * FROM files WHERE id = ?")
		.bind(file_name)
		.first()
	if (!response) {
		return new Response('File not found', { status: 404 });
	}
	let data = await (await env.privatise_storage.get(file_name))?.arrayBuffer();
	if (!data) {
		return new Response('File not found', { status: 404 });
	}
	let raw_key = Uint8Array.from(atob(key), c => c.charCodeAt(0));
	let raw_nonce = Uint8Array.from(atob(nonce), c => c.charCodeAt(0));
	const aes_key = await crypto.subtle.importKey('raw', raw_key, 'AES-GCM', false, ['decrypt']);
	try {
		let actual_data = await crypto.subtle.decrypt(
			{
				name: "AES-GCM",
				iv: raw_nonce,
			},
			aes_key,
			data
		)
		let bytes = new Uint8Array(actual_data);
		if (bytes.length > 1024) {
			// big files are spooky
			bytes = bytes.subarray(0, 1024);
		}
		return new Response(actual_data, {
			headers: {
				'Content-Type': await detect_mime(bytes) || 'application/octet-stream',
				'Content-Disposition': `attachment; filename="${file_name}.${response.original_file_extension}"`,
			},
		} as ResponseInit);
	} catch {
		return new Response('Decryption failed', { status: 400 });
	}
}

function random_string(length: number): string {
	let result = '';
	const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	for (let i = 0; i < length; i++) {
		result += characters.charAt(Math.floor(Math.random() * characters.length));
	}
	return result;
}

async function check_file(bytes: Uint8Array): Promise<[boolean, { entropy: number, known_magic_numbers?: boolean, mostly_printable?: number, possiblity_text_detected?: boolean }]> {
	// binary
	if (mostly_printable(bytes) < 0.8) {
		return [entropy(bytes) >= 6.5 && !(await known_magic_numbers(bytes)), {
			entropy: entropy(bytes),
			known_magic_numbers: await known_magic_numbers(bytes),
			mostly_printable: mostly_printable(bytes)
		}];
	} else {
		return [false, {
			entropy: entropy(bytes),
			mostly_printable: mostly_printable(bytes),
			possiblity_text_detected: true
		}];
	}
}

// simple check if something is very random (to confirm that its an encrypted file)
function entropy(bytes: Uint8Array): number {
	let counter: {[key: number] : number} = {}; // count the occurences of each byte
	for (let i = 0; i < bytes.length; i++) {
		counter[bytes[i]] = (counter[bytes[i]] || 0) + 1;
	}
	let total = bytes.length;
	return -(
		sum(Object.values(counter).map((x) => {
			return x / total * Math.log2(x / total);
		}))
	)
}

function mostly_printable(bytes: Uint8Array): number {
	let printable = sum(
		bytes.map((x) => {
			return (32 <= x && x < 127) ? 1 : 0;
		})
	)
	return (printable / bytes.length);
}

async function known_magic_numbers(bytes: Uint8Array): Promise<boolean> {
	if (bytes.length > 1024) {
		// big files are spooky
		bytes = bytes.subarray(0, 1024);
	}
	try {
		return (!await detect_mime(bytes))
	} catch (e) {
		return false;
	}
}

// binding for mmmagic because they are stupid with their callbacks
async function detect_mime(bytes: Uint8Array): Promise<string> {
	const file_type = await fileTypeFromBuffer(bytes);
	if (!file_type) {
		return 'application/octet-stream';
	}
	return file_type.mime;
}

function sum(it: Iterable<number>): number {
	let total = 0;
	for (const x of it) {
		total += x;
	}
	return total;
}
