import fastify, { FastifyReply, FastifyRequest } from 'fastify'
import spawn from 'child_process'
import cors from '@fastify/cors'
import { z } from "zod";
import { isIP, BlockList, IPVersion } from 'net';
import isValidDomain from 'is-valid-domain';

const server = fastify()
server.register(cors, {
    origin: process.env.CORS_ORIGIN || "*"
})
server.register(import('@fastify/rate-limit'), {
    max: 30,
    timeWindow: '1 minute'
})

const blockList = new BlockList();

blockList.addSubnet('10.0.0.0', 8, 'ipv4'); // RFC1918 - Private Use
blockList.addSubnet('100.64.0.0', 10, 'ipv4'); // RFC6598 - CGNAT
blockList.addSubnet('172.16.0.0', 12, 'ipv4'); // RFC1918 - Private Use
blockList.addSubnet('192.168.0.0', 16, 'ipv4'); // RFC1918 - Private Use
blockList.addSubnet('fc00::', 7, 'ipv6'); // RFC4193 - ULA

const validateSubnet = (subnet: string) => {
    const ip = subnet.split('/')[0]
    const ipVersion = isIP(ip)
    const cidr = subnet.split('/')[1] as unknown as number
    if (isNaN(cidr)) {
        return false
    }
    if (subnet.split('/').length !== 2) {
        return false
    }
    if (ipVersion === 4) {
        if (cidr < 0 || cidr > 32) {
            return false
        }
        return true
    }
    if (ipVersion === 6) {
        if (cidr < 0 || cidr > 128) {
            return false
        }
        return true
    }

    return false
}

const isInBlocklist = (input: string) => {
    const ipVersion = isIP(input);

    if (ipVersion === 4) {
        return blockList.check(input, 'ipv4');
    } else if (ipVersion === 6) {
        return blockList.check(input, 'ipv6');
    }

    return false;
}

server.get('/', async (request: FastifyRequest, reply: FastifyReply) => {
    return reply.status(200).send({ "message": "https://github.com/KittensAreDaBest/caramel" })
})

server.post('/lg', async (request: FastifyRequest, reply: FastifyReply) => {
    let validation
    try {
        validation = z.object({
            type: z.enum(["mtr", "traceroute", "ping", "bgp"]),
            target: z.string().trim(),
        }).parse(request.body)
    } catch (err) {
        return reply.status(400).send({ "error": err })
    }
    const remoteIp = request.headers['x-forwarded-for'] || request.socket.remoteAddress
    console.log(`[${new Date()}][LG] ${validation.type} ${validation.target} from ${remoteIp}`)
    switch (validation.type) {
        case "mtr":
            if (!(process.env.PINGTRACE_ENABLED === "true")) {
                return reply.status(400).send({ "error": "MTR is disabled" });
            }
            if (!isIP(validation.target) && !isValidDomain(validation.target)) {
                return reply.status(400).send({ "error": "Invalid IP/Domain" });
            }
            if (isInBlocklist(validation.target)) {
                return reply.status(400).send({ "error": "Invalid IP/Domain (Bogon)" });
            }
            const mtr = spawn.spawnSync('mtr', ['-c', '5', '-r', '-w', '-b', validation.target]);
            return reply.status(200).send({ "data": mtr.stdout.toString().length > 0 ? mtr.stdout.toString() : mtr.stderr.toString() });

        case "traceroute":
            if (!(process.env.PINGTRACE_ENABLED === "true")) {
                return reply.status(400).send({ "error": "Traceroute is disabled" });
            }
            if (!isIP(validation.target) && !isValidDomain(validation.target)) {
                return reply.status(400).send({ "error": "Invalid IP/Domain" });
            }
            if (isInBlocklist(validation.target)) {
                return reply.status(400).send({ "error": "Invalid IP/Domain (Bogon)" });
            }
            const traceroute = spawn.spawnSync('traceroute', ['-w', '1', '-q', '1', validation.target]);
            return reply.status(200).send({ "data": traceroute.stdout.toString().length > 0 ? traceroute.stdout.toString() : traceroute.stderr.toString() });

        case "ping":
            if (!(process.env.PINGTRACE_ENABLED === "true")) {
                return reply.status(400).send({ "error": "Ping is disabled" });
            }
            if (!isIP(validation.target) && !isValidDomain(validation.target)) {
                return reply.status(400).send({ "error": "Invalid IP/Domain" });
            }
            if (isInBlocklist(validation.target)) {
                return reply.status(400).send({ "error": "Invalid IP/Domain (Bogon)" });
            }
            const ping = spawn.spawnSync('ping', ['-c', '5', validation.target]);
            return reply.status(200).send({ "data": ping.stdout.toString().length > 0 ? ping.stdout.toString() : ping.stderr.toString() });

        case "bgp":
            if (!(process.env.BGP_ENABLED === "true")) {
                return reply.status(400).send({ "error": "BGP is disabled" });
            }
            if (!isIP(validation.target) && !validateSubnet(validation.target)) {
                return reply.status(400).send({ "error": "Invalid IP/CIDR" });
            }
            const bgp = spawn.spawnSync('birdc', ['-r', 'sh', 'ro', 'all', 'for', validation.target]);
            return reply.status(200).send({ "data": bgp.stdout.toString().length > 0 ? bgp.stdout.toString() : bgp.stderr.toString() });

        default:
            return reply.status(400).send({ "error": "Invalid type" });
    }
})

server.listen({ port: 8080, host: "0.0.0.0" }, (err: any, address: string) => {
    if (err) {
        console.error(err)
        process.exit(1)
    }
    console.log(`Server listening at ${address}`)
})