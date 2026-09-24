import {indexerHealth} from '../../monitor/indexer-proxy.mjs';
export const onRequest=({request})=>indexerHealth(request);
