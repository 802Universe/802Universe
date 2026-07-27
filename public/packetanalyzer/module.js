function $parcel$export(e, n, v, s) {
  Object.defineProperty(e, n, {get: v, set: s, enumerable: true, configurable: true});
}
var $81c1b644006d48ec$exports = {};

$parcel$export($81c1b644006d48ec$exports, "PrefSetResult", () => $81c1b644006d48ec$export$9511720e10589113);
$parcel$export($81c1b644006d48ec$exports, "PrefType", () => $81c1b644006d48ec$export$eeff8db21dc74b3d);
let $81c1b644006d48ec$export$9511720e10589113;
(function(PrefSetResult) {
    PrefSetResult[PrefSetResult["PREFS_SET_OK"] = 0] = "PREFS_SET_OK";
    PrefSetResult[PrefSetResult["PREFS_SET_SYNTAX_ERR"] = 1] = "PREFS_SET_SYNTAX_ERR";
    PrefSetResult[PrefSetResult["PREFS_SET_NO_SUCH_PREF"] = 2] = "PREFS_SET_NO_SUCH_PREF";
    PrefSetResult[PrefSetResult["PREFS_SET_OBSOLETE"] = 3] = "PREFS_SET_OBSOLETE";
})($81c1b644006d48ec$export$9511720e10589113 || ($81c1b644006d48ec$export$9511720e10589113 = {}));
let $81c1b644006d48ec$export$eeff8db21dc74b3d;
(function(PrefType) {
    PrefType[PrefType["PREF_UINT"] = 1] = "PREF_UINT";
    PrefType[PrefType["PREF_BOOL"] = 2] = "PREF_BOOL";
    PrefType[PrefType["PREF_ENUM"] = 4] = "PREF_ENUM";
    PrefType[PrefType["PREF_STRING"] = 8] = "PREF_STRING";
    PrefType[PrefType["PREF_RANGE"] = 16] = "PREF_RANGE";
    PrefType[PrefType["PREF_STATIC_TEXT"] = 32] = "PREF_STATIC_TEXT";
    PrefType[PrefType["PREF_UAT"] = 64] = "PREF_UAT";
    PrefType[PrefType["PREF_SAVE_FILENAME"] = 128] = "PREF_SAVE_FILENAME";
    PrefType[PrefType["PREF_COLOR"] = 256] = "PREF_COLOR";
    PrefType[PrefType["PREF_CUSTOM"] = 512] = "PREF_CUSTOM";
    PrefType[PrefType["PREF_OBSOLETE"] = 1024] = "PREF_OBSOLETE";
    PrefType[PrefType["PREF_DIRNAME"] = 2048] = "PREF_DIRNAME";
    PrefType[PrefType["PREF_DECODE_AS_UINT"] = 4096] = "PREF_DECODE_AS_UINT";
    PrefType[PrefType["PREF_DECODE_AS_RANGE"] = 8192] = "PREF_DECODE_AS_RANGE";
    PrefType[PrefType["PREF_OPEN_FILENAME"] = 16384] = "PREF_OPEN_FILENAME";
    PrefType[PrefType["PREF_PASSWORD"] = 32768] = "PREF_PASSWORD";
})($81c1b644006d48ec$export$eeff8db21dc74b3d || ($81c1b644006d48ec$export$eeff8db21dc74b3d = {}));


var $fab42eb3dee39b5b$exports = {};

$parcel$export($fab42eb3dee39b5b$exports, "vectorToArray", () => $fab42eb3dee39b5b$export$4b978bcb0889dc66);
$parcel$export($fab42eb3dee39b5b$exports, "preferenceSetCodeToError", () => $fab42eb3dee39b5b$export$a6506e3cba6c4388);

function $fab42eb3dee39b5b$export$4b978bcb0889dc66(vec) {
    return new Array(vec.size()).fill(0).map((_, id)=>vec.get(id));
}
function $fab42eb3dee39b5b$export$a6506e3cba6c4388(code) {
    switch(code){
        case (0, $81c1b644006d48ec$export$9511720e10589113).PREFS_SET_SYNTAX_ERR:
            return "Syntax error in string";
        case (0, $81c1b644006d48ec$export$9511720e10589113).PREFS_SET_NO_SUCH_PREF:
            return "No such preference";
        case (0, $81c1b644006d48ec$export$9511720e10589113).PREFS_SET_OBSOLETE:
            return "Preference used to exist but no longer does";
        default:
            return "Unknown error";
    }
}




const $149c1bd638913645$var$ALLOWED_TAP_KEYS = new Set([
    ...Array.from({
        length: 15
    }, (_, i)=>`tap${i}`),
    ...Array.from({
        length: 15
    }, (_, i)=>`filter${i}`)
]);
const $149c1bd638913645$var$ALLOWED_GRAPH_KEYS = new Set([
    "filter",
    "interval",
    ...Array.from({
        length: 9
    }, (_, i)=>`graph${i}`),
    ...Array.from({
        length: 9
    }, (_, i)=>`filter${i}`)
]);
class $149c1bd638913645$export$c4e6ddb7806910b1 {
    constructor(){
        this.initialized = false;
        this.session = null;
    }
    /**
   * Initialize the wrapper and the Wiregasm module
   *
   * @param loader Loader function for the Emscripten module
   * @param overrides Overrides
   */ async init(loader, overrides = {}, beforeInit = null) {
        if (this.initialized) return;
        this.lib = await loader(overrides);
        if (beforeInit !== null) await beforeInit(this.lib);
        if (!this.lib.init()) throw new Error("Failed to initialize Wiregasm");
        this.uploadDir = this.lib.getUploadDirectory();
        this.pluginsDir = this.lib.getPluginsDirectory();
        this.initialized = true;
    }
    list_modules() {
        return this.lib.listModules();
    }
    list_prefs(module) {
        return this.lib.listPreferences(module);
    }
    apply_prefs() {
        this.lib.applyPreferences();
    }
    set_pref(module, key, value) {
        const ret = this.lib.setPref(module, key, value);
        if (ret.code != (0, $81c1b644006d48ec$export$9511720e10589113).PREFS_SET_OK) {
            const message = ret.error != "" ? ret.error : (0, $fab42eb3dee39b5b$export$a6506e3cba6c4388)(ret.code);
            throw new Error(`Failed to set preference (${module}.${key}): ${message}`);
        }
    }
    get_pref(module, key) {
        const response = this.lib.getPref(module, key);
        if (response.code != 0) throw new Error(`Failed to get preference (${module}.${key})`);
        return response.data;
    }
    /**
   * Check the validity of a filter expression.
   *
   * @param filter A display filter expression
   */ test_filter(filter) {
        return this.lib.checkFilter(filter);
    }
    complete_filter(filter) {
        const out = this.lib.completeFilter(filter);
        return {
            fields: (0, $fab42eb3dee39b5b$export$4b978bcb0889dc66)(out.fields)
        };
    }
    tap(taps) {
        // Validate keys.
        if (!("tap0" in taps)) throw new Error("tap0 is mandatory.");
        if (!Object.keys(taps).every((k)=>$149c1bd638913645$var$ALLOWED_TAP_KEYS.has(k))) throw new Error(`Invalid arguments. Allowed keys are: ${Array.from($149c1bd638913645$var$ALLOWED_GRAPH_KEYS).join(", ")}.`);
        const args = new this.lib.MapInput();
        Object.entries(taps).forEach(([k, v])=>args.set(k, v));
        const response = this.session.tap(args);
        return {
            error: response.error,
            taps: (0, $fab42eb3dee39b5b$export$4b978bcb0889dc66)(response.taps).map((tap)=>{
                let res;
                if (this.is_conv_tap(tap)) res = {
                    proto: tap.proto,
                    tap: tap.tap,
                    type: tap.type,
                    geoip: tap.geoip,
                    convs: (0, $fab42eb3dee39b5b$export$4b978bcb0889dc66)(tap.convs),
                    hosts: (0, $fab42eb3dee39b5b$export$4b978bcb0889dc66)(tap.hosts)
                };
                else if (this.is_eo_tap(tap)) res = {
                    proto: tap.proto,
                    tap: tap.tap,
                    type: tap.type,
                    objects: (0, $fab42eb3dee39b5b$export$4b978bcb0889dc66)(tap.objects)
                };
                else {
                    tap.delete();
                    throw new Error("Unknown tap result");
                }
                tap.delete();
                return res;
            })
        };
    }
    download(token) {
        return this.session.download(token);
    }
    iograph(input) {
        // Validate keys.
        if (!("graph0" in input)) throw new Error("graph0 is mandatory.");
        if (!Object.keys(input).every((k)=>$149c1bd638913645$var$ALLOWED_GRAPH_KEYS.has(k))) throw new Error(`Invalid arguments. Allowed keys are: ${Array.from($149c1bd638913645$var$ALLOWED_GRAPH_KEYS).join(", ")}.`);
        const args = new this.lib.MapInput();
        Object.entries(input).forEach(([k, v])=>args.set(k, v));
        const out = this.session.iograph(args);
        return {
            ...out,
            iograph: (0, $fab42eb3dee39b5b$export$4b978bcb0889dc66)(out.iograph).map((t)=>({
                    items: (0, $fab42eb3dee39b5b$export$4b978bcb0889dc66)(t.items)
                }))
        };
    }
    reload_lua_plugins() {
        this.lib.reloadLuaPlugins();
    }
    add_plugin(name, data, opts = {}) {
        const path = this.pluginsDir + "/" + name;
        this.lib.FS.writeFile(path, data, opts);
    }
    /**
   * Load a packet trace file for analysis.
   *
   * @returns Response containing the status and summary
   */ load(name, data, opts = {}) {
        if (this.session != null) this.session.delete();
        const path = this.uploadDir + "/" + name;
        this.lib.FS.writeFile(path, data, opts);
        this.session = new this.lib.DissectSession(path);
        return this.session.load();
    }
    /**
   * Get Packet List information for a range of packets.
   *
   * @param filter Output those frames that pass this filter expression
   * @param skip Skip N frames
   * @param limit Limit the output to N frames
   */ frames(filter, skip = 0, limit = 0) {
        return this.session.getFrames(filter, skip, limit);
    }
    /**
   * Get full information about a frame including the protocol tree.
   *
   * @param number Frame number
   */ frame(num) {
        return this.session.getFrame(num);
    }
    follow(follow, filter) {
        return this.session.follow(follow, filter);
    }
    destroy() {
        if (this.initialized) {
            if (this.session !== null) {
                this.session.delete();
                this.session = null;
            }
            this.lib.destroy();
            this.initialized = false;
        }
    }
    /**
   * Returns the column headers
   */ columns() {
        const vec = this.lib.getColumns();
        // convert it from a vector to array
        return (0, $fab42eb3dee39b5b$export$4b978bcb0889dc66)(vec);
    }
    is_eo_tap(tap) {
        return tap instanceof this.lib.TapExportObject;
    }
    is_conv_tap(tap) {
        return tap instanceof this.lib.TapConvResponse;
    }
}


export {$149c1bd638913645$export$c4e6ddb7806910b1 as Wiregasm, $81c1b644006d48ec$export$9511720e10589113 as PrefSetResult, $81c1b644006d48ec$export$eeff8db21dc74b3d as PrefType, $fab42eb3dee39b5b$export$4b978bcb0889dc66 as vectorToArray, $fab42eb3dee39b5b$export$a6506e3cba6c4388 as preferenceSetCodeToError};
//# sourceMappingURL=module.js.map
