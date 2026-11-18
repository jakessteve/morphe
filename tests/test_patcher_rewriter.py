# ---------------------------------------------------------
# Copyright (C) 2026 krvstek (Original Author)
# Copyright (C) 2026 The uni-apks Contributors (Modifications)
#
# DO NOT REMOVE OR ALTER THIS COPYRIGHT HEADER.
# This file is part of uni-apks.
# Canonical source: https://github.com/krvstek/uni-apks
#
# Licensed under the GNU GPLv3. You may modify this file,
# but you MUST keep this original copyright notice intact
# and prominently state any changes made.
# See the AUTHORS file in the root directory for details.
# ---------------------------------------------------------
# pyright: reportPrivateUsage=false

import os
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import src.core.patcher as patcher_mod
from src.core.patcher import PatcherCLI, _ensure_helper_java, _java_bin

_CLIENT_TYPE_JAVA = """
package app.morphe.extension.shared.spoof;

public enum ClientType {
    TV_SIMPLY(true, true, false),
    TV_SABR(true, false, false),
    TV_SABR_WII_U(true, false, false),
    VISIONOS_1_02(false, false, false),
    ANDROID_MUSIC_NO_SDK(false, false, false),
    ANDROID_MUSIC_REEL(false, false, false),
    ANDROID_CREATOR(false, false, true),
    ANDROID_VR_DASH(false, false, true),
    MWEB(true, false, false);

    public final boolean requireJS;
    public final boolean requirePoToken;
    public final boolean supportsOAuth2;

    ClientType(boolean requireJS, boolean requirePoToken, boolean supportsOAuth2) {
        this.requireJS = requireJS;
        this.requirePoToken = requirePoToken;
        this.supportsOAuth2 = supportsOAuth2;
    }
}
"""

_SHARED_STUBS_JAVA = """
package app.morphe.extension.shared.patches;

public final class AppCheckPatch {
    public static boolean IS_YOUTUBE = true;
    public static boolean IS_YOUTUBE_MUSIC = false;
}
"""

_POTOKEN_MANAGER_JAVA = """
package app.morphe.extension.shared.spoof.potoken;

import app.morphe.extension.shared.spoof.ClientType;

public final class PoTokenManager {
    private PoTokenManager() {}

    public static Object getAndUpdatePoTokenIfNeeded(ClientType clientType, String videoId) {
        return videoId == null ? "tok" : videoId.trim();
    }

    public static String getPlayerPoToken(ClientType clientType, String videoId) {
        return videoId == null ? "player-tok" : videoId.trim();
    }

    public static String getStreamingPoToken(ClientType clientType, String videoId) {
        return videoId == null ? "stream-tok" : videoId.trim();
    }
}
"""

_POTOKEN_PROVIDER_PATCH_JAVA = """
package app.morphe.extension.shared.patches;

public final class PoTokenProviderPatch {
    public static boolean REJECTED = false;

    private static boolean useExternalPoTokenProvider(String serviceAction) {
        return serviceAction != null && !serviceAction.isEmpty();
    }

    private static boolean isPoTokenProviderAvailable() {
        return !REJECTED;
    }

    private static boolean isHelperInUse() {
        return !REJECTED;
    }

    private static synchronized void onTokenRejected(String reason) {
        if (reason != null) {
            REJECTED = true;
        }
    }
}
"""

_JS_SUPPORT_JAVA = """
package app.morphe.extension.shared.spoof.js;

public final class JavaScriptEngineSupport {
    public static boolean SUPPORTS_JS = false;

    public static boolean supportsJavaScriptEngine() {
        return SUPPORTS_JS;
    }
}
"""

_STREAMING_DATA_REQUEST_JAVA = """
package app.morphe.extension.shared.spoof.requests;

import app.morphe.extension.shared.spoof.ClientType;
import app.morphe.extension.shared.spoof.js.JavaScriptEngineSupport;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class StreamingDataRequest {
    public static final class StreamData {}

    public static boolean OAUTH_CHECKED = false;
    private static final String AUTHORIZATION_HEADER = "Authorization";

    public final String videoId;
    public final String authorization;
    public final ClientType[] clientOrder;

    public StreamingDataRequest(
        String videoId,
        Map<String, String> playerHeaders,
        boolean includeVideoDetails,
        ClientType[] clientOrder,
        boolean isDownload
    ) {
        this.videoId = videoId;
        this.authorization = playerHeaders.get(AUTHORIZATION_HEADER);
        this.clientOrder = clientOrder;
    }

    public boolean isFetchInProgress(Map<String, String> playerHeaders, ClientType[] clientOrder) {
        return this.clientOrder == clientOrder
            && Objects.equals(this.authorization, playerHeaders.get(AUTHORIZATION_HEADER));
    }

    private static List<ClientType> buildClientOrder(
        List<ClientType> availableClients,
        ClientType preferredClient
    ) {
        Objects.requireNonNull(preferredClient);

        List<ClientType> orderToUse = new ArrayList<>(availableClients.size());
        orderToUse.add(preferredClient);
        if (preferredClient == ClientType.TV_SABR) {
            orderToUse.add(ClientType.TV_SABR_WII_U);
        }

        for (ClientType client : availableClients) {
            if (client.requireJS && !JavaScriptEngineSupport.supportsJavaScriptEngine()) {
                continue;
            }
            if (client != preferredClient) {
                orderToUse.add(client);
            }
        }

        return orderToUse;
    }

    private static StreamData fetch(
        String videoId,
        Map<String, String> playerHeaders,
        boolean includeVideoDetails,
        ClientType[] clientOrder,
        boolean isDownload
    ) {
        String authorization = playerHeaders.get(AUTHORIZATION_HEADER);
        for (ClientType clientType : clientOrder) {
            if (clientType == null && authorization != null) {
                return new StreamData();
            }
        }
        if (isDownload) {
            return null;
        }
        ClientType preferredClient = clientOrder[0];
        if (!preferredClient.supportsOAuth2) {
            OAUTH_CHECKED = true;
        }
        return null;
    }
}
"""

_MUSIC_SETTINGS_JAVA = """
package app.morphe.extension.music.settings;

import app.morphe.extension.shared.spoof.ClientType;

public final class Settings {
    public static final ClientType DEFAULT_CLIENT = ClientType.TV_SIMPLY;
}
"""

_MUSIC_PATCH_TEMPLATE_JAVA = """
package app.morphe.extension.music.patches.spoof;

import app.morphe.extension.shared.spoof.ClientType;
import java.util.List;

public final class SpoofVideoStreamsPatch {
    public static final List<ClientType> AVAILABLE_CLIENTS = List.of(
        ClientType.__FIRST_CLIENT__,
        ClientType.VISIONOS_1_02,
        ClientType.ANDROID_MUSIC_NO_SDK,
        ClientType.ANDROID_MUSIC_REEL
    );
}
"""

_YT_SETTINGS_JAVA = """
package app.morphe.extension.youtube.settings;

import app.morphe.extension.shared.spoof.ClientType;

public final class Settings {
    public static final ClientType DEFAULT_CLIENT = ClientType.TV_SIMPLY;
}
"""

_YT_PATCH_JAVA = """
package app.morphe.extension.youtube.patches.spoof;

import app.morphe.extension.shared.spoof.ClientType;
import java.util.List;

public final class SpoofVideoStreamsPatch {
    public static List<ClientType> LAST_AVAILABLE;

    public static void setClientOrderToUse() {
        LAST_AVAILABLE = List.of(ClientType.TV_SIMPLY, ClientType.ANDROID_CREATOR);
    }
}
"""

_SMALI_STUB_JAVA = """
package com.android.tools.smali.smali;

import java.util.List;

public final class Smali {
    public static boolean assemble(SmaliOptions options, List<String> input) {
        throw new UnsupportedOperationException("Smali stub");
    }
}
"""

_SMALI_OPTIONS_STUB_JAVA = """
package com.android.tools.smali.smali;

public final class SmaliOptions {
    public String outputDexFile;
    public int apiLevel = 26;
}
"""

_DEX_VERIFIER_HARNESS_JAVA = r"""
import com.android.tools.smali.dexlib2.DexFileFactory;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.DexFile;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.instruction.FiveRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.iface.instruction.NarrowLiteralInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.OffsetInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.RegisterRangeInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.ThreeRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.TwoRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.reference.FieldReference;
import com.android.tools.smali.dexlib2.iface.reference.MethodReference;
import com.android.tools.smali.dexlib2.iface.reference.StringReference;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class DexVerifierHarness {
    static final class FakeClient {
        final String name;
        final boolean requireJS;
        final boolean supportsOAuth2;

        FakeClient(String name, boolean requireJS, boolean supportsOAuth2) {
            this.name = name;
            this.requireJS = requireJS;
            this.supportsOAuth2 = supportsOAuth2;
        }

        @Override
        public String toString() {
            return name;
        }
    }

    private static final Map<String, FakeClient> CLIENTS = new HashMap<>();
    static {
        CLIENTS.put("TV_SIMPLY", new FakeClient("TV_SIMPLY", true, false));
        CLIENTS.put("TV_SABR", new FakeClient("TV_SABR", true, false));
        CLIENTS.put("TV_SABR_WII_U", new FakeClient("TV_SABR_WII_U", true, false));
        CLIENTS.put("VISIONOS_1_02", new FakeClient("VISIONOS_1_02", false, false));
        CLIENTS.put("ANDROID_MUSIC_NO_SDK", new FakeClient("ANDROID_MUSIC_NO_SDK", false, false));
        CLIENTS.put("ANDROID_MUSIC_REEL", new FakeClient("ANDROID_MUSIC_REEL", false, false));
        CLIENTS.put("ANDROID_CREATOR", new FakeClient("ANDROID_CREATOR", false, true));
        CLIENTS.put("ANDROID_VR_DASH", new FakeClient("ANDROID_VR_DASH", false, true));
        CLIENTS.put("MWEB", new FakeClient("MWEB", true, false));
    }

    private static boolean isYoutubeMusic = false;
    private static boolean supportsJs = false;
    private static boolean oauthChecked = false;

    private static Method findMethod(DexFile dex, String classDesc, String methodName) {
        for (ClassDef cd : dex.getClasses()) {
            if (classDesc.equals(cd.getType())) {
                for (Method m : cd.getMethods()) {
                    if (methodName.equals(m.getName())) {
                        return m;
                    }
                }
            }
        }
        throw new IllegalStateException("Missing method " + classDesc + "->" + methodName);
    }

    private static List<String> collectClientGets(Method m) {
        List<String> out = new ArrayList<>();
        MethodImplementation impl = Objects.requireNonNull(m.getImplementation());
        for (Instruction ins : impl.getInstructions()) {
            if (ins.getOpcode() == Opcode.SGET_OBJECT && ins instanceof ReferenceInstruction) {
                FieldReference fr = (FieldReference) ((ReferenceInstruction) ins).getReference();
                if ("Lapp/morphe/extension/shared/spoof/ClientType;".equals(fr.getDefiningClass())) {
                    out.add(fr.getName());
                }
            }
        }
        return out;
    }

    private static int[] extractArgs(Instruction ins) {
        if (ins instanceof FiveRegisterInstruction) {
            FiveRegisterInstruction f = (FiveRegisterInstruction) ins;
            int n = f.getRegisterCount();
            int[] raw = {f.getRegisterC(), f.getRegisterD(), f.getRegisterE(), f.getRegisterF(), f.getRegisterG()};
            int[] out = new int[n];
            System.arraycopy(raw, 0, out, 0, n);
            return out;
        }
        if (ins instanceof RegisterRangeInstruction) {
            RegisterRangeInstruction r = (RegisterRangeInstruction) ins;
            int[] out = new int[r.getRegisterCount()];
            for (int i = 0; i < out.length; i++) {
                out[i] = r.getStartRegister() + i;
            }
            return out;
        }
        throw new IllegalStateException("Unsupported invoke format: " + ins.getOpcode());
    }

    private static boolean asBool(Object v) {
        if (v == null) return false;
        if (v instanceof Boolean) return (Boolean) v;
        if (v instanceof Number) return ((Number) v).intValue() != 0;
        throw new IllegalStateException("Expected boolean/int, got: " + v);
    }

    private static int asInt(Object v) {
        if (v == null) return 0;
        if (v instanceof Boolean) return ((Boolean) v) ? 1 : 0;
        if (v instanceof Number) return ((Number) v).intValue();
        throw new IllegalStateException("Expected int, got: " + v);
    }

    @SuppressWarnings("unchecked")
    private static Object interpret(Method m, Object... params) {
        MethodImplementation impl = Objects.requireNonNull(m.getImplementation());
        List<Instruction> insns = new ArrayList<>();
        Map<Integer, Integer> addrToIdx = new HashMap<>();
        List<Integer> idxToAddr = new ArrayList<>();
        int addr = 0;
        for (Instruction ins : impl.getInstructions()) {
            addrToIdx.put(addr, insns.size());
            idxToAddr.add(addr);
            insns.add(ins);
            addr += ins.getCodeUnits();
        }

        int regCount = impl.getRegisterCount();
        Object[] regs = new Object[regCount];
        int paramStart = regCount - params.length;
        for (int i = 0; i < params.length; i++) {
            regs[paramStart + i] = params[i];
        }

        Object lastResult = null;
        int pc = 0;
        int steps = 0;
        while (pc < insns.size()) {
            if (++steps > 10000) {
                throw new IllegalStateException("Infinite loop in interpreter");
            }
            Instruction ins = insns.get(pc);
            Opcode op = ins.getOpcode();
            switch (op) {
                case NOP:
                    pc++;
                    break;
                case CONST_4:
                case CONST_16:
                case CONST: {
                    int reg = ((OneRegisterInstruction) ins).getRegisterA();
                    int lit = ((NarrowLiteralInstruction) ins).getNarrowLiteral();
                    regs[reg] = (lit == 0) ? null : Integer.valueOf(lit);
                    pc++;
                    break;
                }
                case CONST_STRING:
                case CONST_STRING_JUMBO: {
                    int reg = ((OneRegisterInstruction) ins).getRegisterA();
                    regs[reg] = ((StringReference) ((ReferenceInstruction) ins).getReference()).getString();
                    pc++;
                    break;
                }
                case MOVE:
                case MOVE_FROM16:
                case MOVE_OBJECT:
                case MOVE_OBJECT_FROM16: {
                    TwoRegisterInstruction t = (TwoRegisterInstruction) ins;
                    regs[t.getRegisterA()] = regs[t.getRegisterB()];
                    pc++;
                    break;
                }
                case MOVE_RESULT:
                case MOVE_RESULT_OBJECT: {
                    regs[((OneRegisterInstruction) ins).getRegisterA()] = lastResult;
                    pc++;
                    break;
                }
                case CHECK_CAST: {
                    pc++;
                    break;
                }
                case NEW_INSTANCE: {
                    int reg = ((OneRegisterInstruction) ins).getRegisterA();
                    regs[reg] = new ArrayList<>();
                    pc++;
                    break;
                }
                case ARRAY_LENGTH: {
                    TwoRegisterInstruction t = (TwoRegisterInstruction) ins;
                    Object[] arr = (Object[]) Objects.requireNonNull(regs[t.getRegisterB()], "null array");
                    regs[t.getRegisterA()] = Integer.valueOf(arr.length);
                    pc++;
                    break;
                }
                case AGET_OBJECT: {
                    ThreeRegisterInstruction t = (ThreeRegisterInstruction) ins;
                    Object[] arr = (Object[]) Objects.requireNonNull(regs[t.getRegisterB()], "null array");
                    int idx = asInt(regs[t.getRegisterC()]);
                    regs[t.getRegisterA()] = arr[idx];
                    pc++;
                    break;
                }
                case ADD_INT_LIT8: {
                    TwoRegisterInstruction t = (TwoRegisterInstruction) ins;
                    int lit = ((NarrowLiteralInstruction) ins).getNarrowLiteral();
                    regs[t.getRegisterA()] = Integer.valueOf(asInt(regs[t.getRegisterB()]) + lit);
                    pc++;
                    break;
                }
                case SGET_OBJECT: {
                    int reg = ((OneRegisterInstruction) ins).getRegisterA();
                    FieldReference fr = (FieldReference) ((ReferenceInstruction) ins).getReference();
                    if ("Lapp/morphe/extension/shared/spoof/ClientType;".equals(fr.getDefiningClass())) {
                        regs[reg] = Objects.requireNonNull(CLIENTS.get(fr.getName()), "Unknown client " + fr.getName());
                    } else {
                        throw new IllegalStateException("Unsupported sget-object: " + fr);
                    }
                    pc++;
                    break;
                }
                case SGET_BOOLEAN: {
                    int reg = ((OneRegisterInstruction) ins).getRegisterA();
                    FieldReference fr = (FieldReference) ((ReferenceInstruction) ins).getReference();
                    if ("IS_YOUTUBE_MUSIC".equals(fr.getName())) {
                        regs[reg] = Boolean.valueOf(isYoutubeMusic);
                    } else if ("OAUTH_CHECKED".equals(fr.getName())) {
                        regs[reg] = Boolean.valueOf(oauthChecked);
                    } else {
                        throw new IllegalStateException("Unsupported sget-boolean: " + fr);
                    }
                    pc++;
                    break;
                }
                case SPUT_BOOLEAN: {
                    int reg = ((OneRegisterInstruction) ins).getRegisterA();
                    FieldReference fr = (FieldReference) ((ReferenceInstruction) ins).getReference();
                    if ("OAUTH_CHECKED".equals(fr.getName())) {
                        oauthChecked = asBool(regs[reg]);
                    }
                    pc++;
                    break;
                }
                case IGET_BOOLEAN: {
                    TwoRegisterInstruction t = (TwoRegisterInstruction) ins;
                    FakeClient c = (FakeClient) Objects.requireNonNull(regs[t.getRegisterB()], "null FakeClient");
                    FieldReference fr = (FieldReference) ((ReferenceInstruction) ins).getReference();
                    if ("requireJS".equals(fr.getName())) {
                        regs[t.getRegisterA()] = Boolean.valueOf(c.requireJS);
                    } else if ("supportsOAuth2".equals(fr.getName())) {
                        regs[t.getRegisterA()] = Boolean.valueOf(c.supportsOAuth2);
                    } else {
                        throw new IllegalStateException("Unsupported iget-boolean: " + fr);
                    }
                    pc++;
                    break;
                }
                case IGET_OBJECT: {
                    TwoRegisterInstruction t = (TwoRegisterInstruction) ins;
                    Map<String, Object> self = (Map<String, Object>) Objects.requireNonNull(regs[t.getRegisterB()]);
                    FieldReference fr = (FieldReference) ((ReferenceInstruction) ins).getReference();
                    regs[t.getRegisterA()] = self.get(fr.getName());
                    pc++;
                    break;
                }
                case IPUT_OBJECT: {
                    TwoRegisterInstruction t = (TwoRegisterInstruction) ins;
                    Map<String, Object> self = (Map<String, Object>) Objects.requireNonNull(regs[t.getRegisterB()]);
                    FieldReference fr = (FieldReference) ((ReferenceInstruction) ins).getReference();
                    self.put(fr.getName(), regs[t.getRegisterA()]);
                    pc++;
                    break;
                }
                case INVOKE_STATIC:
                case INVOKE_DIRECT:
                case INVOKE_VIRTUAL:
                case INVOKE_INTERFACE:
                case INVOKE_STATIC_RANGE:
                case INVOKE_DIRECT_RANGE:
                case INVOKE_VIRTUAL_RANGE:
                case INVOKE_INTERFACE_RANGE: {
                    MethodReference mr = (MethodReference) ((ReferenceInstruction) ins).getReference();
                    int[] args = extractArgs(ins);
                    String cls = mr.getDefiningClass();
                    String name = mr.getName();
                    if ("Ljava/lang/Object;".equals(cls) && "<init>".equals(name)) {
                        lastResult = null;
                    } else if ("Ljava/util/Objects;".equals(cls) && "requireNonNull".equals(name)) {
                        lastResult = Objects.requireNonNull(regs[args[0]]);
                    } else if ("Ljava/util/Objects;".equals(cls) && "equals".equals(name)) {
                        lastResult = Boolean.valueOf(Objects.equals(regs[args[0]], regs[args[1]]));
                    } else if ("Ljava/util/Collections;".equals(cls) && "emptyMap".equals(name)) {
                        lastResult = Collections.emptyMap();
                    } else if ("Ljava/util/ArrayList;".equals(cls) && "<init>".equals(name)) {
                        lastResult = null;
                    } else if ("Ljava/util/List;".equals(cls) && "size".equals(name)) {
                        lastResult = Integer.valueOf(((List<?>) Objects.requireNonNull(regs[args[0]])).size());
                    } else if ("Ljava/util/List;".equals(cls) && "add".equals(name)) {
                        lastResult = Boolean.valueOf(((List<Object>) Objects.requireNonNull(regs[args[0]])).add(regs[args[1]]));
                    } else if ("Ljava/util/List;".equals(cls) && "contains".equals(name)) {
                        lastResult = Boolean.valueOf(((List<Object>) Objects.requireNonNull(regs[args[0]])).contains(regs[args[1]]));
                    } else if ("Ljava/util/List;".equals(cls) && "iterator".equals(name)) {
                        lastResult = ((List<?>) Objects.requireNonNull(regs[args[0]])).iterator();
                    } else if ("Ljava/util/Iterator;".equals(cls) && "hasNext".equals(name)) {
                        lastResult = Boolean.valueOf(((Iterator<?>) Objects.requireNonNull(regs[args[0]])).hasNext());
                    } else if ("Ljava/util/Iterator;".equals(cls) && "next".equals(name)) {
                        lastResult = ((Iterator<?>) Objects.requireNonNull(regs[args[0]])).next();
                    } else if ("Ljava/util/Map;".equals(cls) && "get".equals(name)) {
                        Map<?, ?> map = (Map<?, ?>) Objects.requireNonNull(regs[args[0]], "NullPointerException on Map.get");
                        lastResult = map.get(regs[args[1]]);
                    } else if ("Lapp/morphe/extension/shared/spoof/js/JavaScriptEngineSupport;".equals(cls)
                        && "supportsJavaScriptEngine".equals(name)) {
                        lastResult = Boolean.valueOf(supportsJs);
                    } else {
                        throw new IllegalStateException("Unsupported invoke: " + mr);
                    }
                    pc++;
                    break;
                }
                case GOTO:
                case GOTO_16:
                case GOTO_32: {
                    int targetAddr = idxToAddr.get(pc) + ((OffsetInstruction) ins).getCodeOffset();
                    pc = Objects.requireNonNull(addrToIdx.get(targetAddr), "Bad goto target");
                    break;
                }
                case IF_EQZ:
                case IF_NEZ: {
                    int reg = ((OneRegisterInstruction) ins).getRegisterA();
                    boolean isZero = (regs[reg] == null)
                        || (regs[reg] instanceof Boolean && !((Boolean) regs[reg]))
                        || (regs[reg] instanceof Number && ((Number) regs[reg]).intValue() == 0);
                    boolean take = (op == Opcode.IF_EQZ) ? isZero : !isZero;
                    if (take) {
                        int targetAddr = idxToAddr.get(pc) + ((OffsetInstruction) ins).getCodeOffset();
                        pc = Objects.requireNonNull(addrToIdx.get(targetAddr), "Bad branch target");
                    } else {
                        pc++;
                    }
                    break;
                }
                case IF_EQ:
                case IF_NE:
                case IF_GE: {
                    TwoRegisterInstruction t = (TwoRegisterInstruction) ins;
                    Object a = regs[t.getRegisterA()];
                    Object b = regs[t.getRegisterB()];
                    boolean take;
                    if (op == Opcode.IF_GE) {
                        take = asInt(a) >= asInt(b);
                    } else {
                        boolean eq = (a == b) || (a instanceof Number && b instanceof Number && asInt(a) == asInt(b));
                        take = (op == Opcode.IF_EQ) ? eq : !eq;
                    }
                    if (take) {
                        int targetAddr = idxToAddr.get(pc) + ((OffsetInstruction) ins).getCodeOffset();
                        pc = Objects.requireNonNull(addrToIdx.get(targetAddr), "Bad branch target");
                    } else {
                        pc++;
                    }
                    break;
                }
                case RETURN_VOID:
                    return null;
                case RETURN:
                case RETURN_OBJECT:
                    return regs[((OneRegisterInstruction) ins).getRegisterA()];
                default:
                    throw new IllegalStateException("Unhandled opcode: " + op);
            }
        }
        return null;
    }

    private static void assertEq(Object expected, Object actual, String msg) {
        if (!Objects.equals(expected, actual)) {
            throw new AssertionError(msg + " | expected=" + expected + " actual=" + actual);
        }
    }

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        String mode = args[0];
        DexFile dex = DexFileFactory.loadDexFile(new File(args[1]), Opcodes.getDefault());

        if ("shared-youtube".equals(mode)) {
            String sdr = "Lapp/morphe/extension/shared/spoof/requests/StreamingDataRequest;";
            Method buildOrder = findMethod(dex, sdr, "buildClientOrder");
            Method fetch = findMethod(dex, sdr, "fetch");
            Method init = findMethod(dex, sdr, "<init>");
            Method inProg = findMethod(dex, sdr, "isFetchInProgress");

            // 1. YouTube: preferred=TV_SABR preserves TV_SABR_WII_U and appends VISIONOS_1_02
            isYoutubeMusic = false;
            supportsJs = false;
            List<FakeClient> ytAvail = List.of(CLIENTS.get("TV_SABR"), CLIENTS.get("ANDROID_CREATOR"));
            List<FakeClient> r1 = (List<FakeClient>) interpret(buildOrder, ytAvail, CLIENTS.get("TV_SABR"));
            assertEq(
                "[TV_SABR, TV_SABR_WII_U, ANDROID_CREATOR, VISIONOS_1_02]",
                r1.toString(),
                "TV_SABR client order"
            );

            // 2. YouTube: preferred=TV_SIMPLY with JS disabled remaps to TV_SABR + TV_SABR_WII_U + VISIONOS_1_02
            isYoutubeMusic = false;
            supportsJs = false;
            List<FakeClient> jsOnlyAvail = List.of(CLIENTS.get("TV_SABR"));
            List<FakeClient> r2 = (List<FakeClient>) interpret(buildOrder, jsOnlyAvail, CLIENTS.get("TV_SIMPLY"));
            assertEq(
                "[TV_SABR, TV_SABR_WII_U, VISIONOS_1_02]",
                r2.toString(),
                "YouTube TV_SIMPLY remap without JS"
            );

            // 3. YouTube Music: preferred=TV_SIMPLY remaps to ANDROID_MUSIC_NO_SDK without duplicating VISIONOS_1_02
            isYoutubeMusic = true;
            supportsJs = false;
            List<FakeClient> ytmAvail = List.of(
                CLIENTS.get("ANDROID_MUSIC_NO_SDK"),
                CLIENTS.get("ANDROID_MUSIC_REEL"),
                CLIENTS.get("TV_SABR"),
                CLIENTS.get("VISIONOS_1_02")
            );
            List<FakeClient> r3 = (List<FakeClient>) interpret(buildOrder, ytmAvail, CLIENTS.get("TV_SIMPLY"));
            assertEq(
                "[ANDROID_MUSIC_NO_SDK, ANDROID_MUSIC_REEL, VISIONOS_1_02]",
                r3.toString(),
                "YT Music TV_SIMPLY remap without JS"
            );

            // 4. Empty availableClients still appends VISIONOS_1_02
            isYoutubeMusic = false;
            supportsJs = false;
            List<FakeClient> r4 = (List<FakeClient>) interpret(buildOrder, Collections.emptyList(), CLIENTS.get("MWEB"));
            assertEq("[MWEB, VISIONOS_1_02]", r4.toString(), "Empty availableClients fallback");

            // 5. fetch with empty clientOrder[] and null playerHeaders returns null without AIOOBE/NPE
            oauthChecked = false;
            Object fEmpty = interpret(fetch, "vid1", null, Boolean.FALSE, new FakeClient[0], Boolean.FALSE);
            assertEq(null, fEmpty, "fetch empty clientOrder must return null");
            assertEq(Boolean.FALSE, Boolean.valueOf(oauthChecked), "empty clientOrder skips supportsOAuth2");

            // 6. fetch with non-empty clientOrder[] and null playerHeaders checks clientOrder[0].supportsOAuth2
            oauthChecked = false;
            Object fNonEmpty = interpret(
                fetch,
                "vid2",
                null,
                Boolean.FALSE,
                new FakeClient[] {CLIENTS.get("TV_SABR")},
                Boolean.FALSE
            );
            assertEq(null, fNonEmpty, "fetch exhausted clientOrder returns null");
            assertEq(Boolean.TRUE, Boolean.valueOf(oauthChecked), "non-empty clientOrder checks supportsOAuth2");

            // 7. <init> and isFetchInProgress guard null playerHeaders
            Map<String, Object> fakeThis = new HashMap<>();
            FakeClient[] orderArr = new FakeClient[] {CLIENTS.get("VISIONOS_1_02")};
            interpret(init, fakeThis, "vid3", null, Boolean.FALSE, orderArr, Boolean.FALSE);
            assertEq(null, fakeThis.get("authorization"), "<init> null headers authorization");
            Object sameFetch = interpret(inProg, fakeThis, null, orderArr);
            assertEq(Boolean.TRUE, Boolean.valueOf(asBool(sameFetch)), "isFetchInProgress null headers");

            for (ClassDef cd : dex.getClasses()) {
                if (cd.getType().contains("SignatureCompatibility")) {
                    throw new AssertionError("Facebook SignatureCompatibility leaked into shared-youtube.mpe");
                }
            }
        } else if ("music".equals(mode)) {
            Method patchClinit = findMethod(
                dex,
                "Lapp/morphe/extension/music/patches/spoof/SpoofVideoStreamsPatch;",
                "<clinit>"
            );
            Method settingsClinit = findMethod(
                dex,
                "Lapp/morphe/extension/music/settings/Settings;",
                "<clinit>"
            );
            assertEq(
                "[ANDROID_MUSIC_NO_SDK, ANDROID_MUSIC_REEL, TV_SABR, VISIONOS_1_02]",
                collectClientGets(patchClinit).toString(),
                "Music SpoofVideoStreamsPatch AVAILABLE_CLIENTS"
            );
            assertEq(
                "[ANDROID_MUSIC_NO_SDK]",
                collectClientGets(settingsClinit).toString(),
                "Music Settings DEFAULT_CLIENT"
            );
        } else if ("youtube".equals(mode)) {
            Method setOrder = findMethod(
                dex,
                "Lapp/morphe/extension/youtube/patches/spoof/SpoofVideoStreamsPatch;",
                "setClientOrderToUse"
            );
            Method settingsClinit = findMethod(
                dex,
                "Lapp/morphe/extension/youtube/settings/Settings;",
                "<clinit>"
            );
            assertEq(
                "[TV_SABR, ANDROID_CREATOR]",
                collectClientGets(setOrder).toString(),
                "YouTube SpoofVideoStreamsPatch setClientOrderToUse"
            );
            assertEq(
                "[TV_SABR]",
                collectClientGets(settingsClinit).toString(),
                "YouTube Settings DEFAULT_CLIENT"
            );
        } else {
            throw new IllegalArgumentException("Unknown mode: " + mode);
        }
    }
}
"""


def _find_javac() -> str:
    java_path = Path(_java_bin())
    sibling = java_path.with_name("javac")
    if sibling.is_file():
        return str(sibling)
    found = shutil.which("javac")
    if found:
        return found
    raise RuntimeError("javac not found")


def _find_d8() -> Path:
    sdk_roots = [
        os.getenv("ANDROID_HOME"),
        os.getenv("ANDROID_SDK_ROOT"),
        str(Path.home() / "Android" / "Sdk"),
        "/opt/android-sdk",
    ]
    for root in sdk_roots:
        if not root:
            continue
        bt = Path(root) / "build-tools"
        if bt.is_dir():
            for ver_dir in sorted(bt.iterdir(), reverse=True):
                d8 = ver_dir / "d8"
                if d8.is_file():
                    return d8
    found = shutil.which("d8")
    if found:
        return Path(found)
    raise RuntimeError("Android SDK d8 not found")


def _build_rewriter_jar(work_dir: Path) -> Path:
    env_jar = os.getenv("MORPHE_CLI_JAR")
    if env_jar and Path(env_jar).is_file():
        return Path(env_jar)

    sdk_roots = [
        os.getenv("ANDROID_HOME"),
        os.getenv("ANDROID_SDK_ROOT"),
        str(Path.home() / "Android" / "Sdk"),
    ]
    for root in sdk_roots:
        if not root:
            continue
        ext = Path(root) / "cmdline-tools" / "latest" / "lib" / "external"
        dexlib2 = next(ext.glob("com/android/tools/smali/smali-dexlib2/*/smali-dexlib2-*.jar"), None) if ext.is_dir() else None
        util = next(ext.glob("com/android/tools/smali/smali-util/*/smali-util-*.jar"), None) if ext.is_dir() else None
        guava = next(ext.glob("com/google/guava/guava/*/guava-*.jar"), None) if ext.is_dir() else None
        bcprov = next(ext.glob("org/bouncycastle/bcprov-jdk15on/*/bcprov-jdk15on-*.jar"), None) if ext.is_dir() else None
        if dexlib2 and util and guava and bcprov:
            stub_src = work_dir / "smali_stubs_src"
            stub_cls = work_dir / "smali_stubs_cls"
            pkg_dir = stub_src / "com" / "android" / "tools" / "smali" / "smali"
            pkg_dir.mkdir(parents=True, exist_ok=True)
            stub_cls.mkdir(parents=True, exist_ok=True)
            (pkg_dir / "Smali.java").write_text(_SMALI_STUB_JAVA, encoding="utf-8")
            (pkg_dir / "SmaliOptions.java").write_text(_SMALI_OPTIONS_STUB_JAVA, encoding="utf-8")
            subprocess.run(
                [
                    _find_javac(),
                    "--release",
                    "17",
                    "-d",
                    str(stub_cls),
                    str(pkg_dir / "Smali.java"),
                    str(pkg_dir / "SmaliOptions.java"),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            bundle_jar = work_dir / "sdk-dexlib2-bundle.jar"
            rel_jars = [os.path.relpath(j, work_dir) for j in (dexlib2, util, guava, bcprov)]
            manifest = f"Manifest-Version: 1.0\nClass-Path: {' '.join(rel_jars)}\n\n"
            with zipfile.ZipFile(bundle_jar, "w") as zf:
                zf.writestr("META-INF/MANIFEST.MF", manifest)
                for cls_file in stub_cls.rglob("*.class"):
                    zf.write(cls_file, cls_file.relative_to(stub_cls).as_posix())
            return bundle_jar

    raise RuntimeError("Neither MORPHE_CLI_JAR nor Android SDK dexlib2 jars found")


def _compile_sources_to_dex(work_dir: Path, name: str, sources: dict[str, str], d8: Path) -> Path:
    src_dir = work_dir / f"{name}_src"
    cls_dir = work_dir / f"{name}_cls"
    dex_dir = work_dir / f"{name}_dex"
    src_dir.mkdir(parents=True, exist_ok=True)
    cls_dir.mkdir(parents=True, exist_ok=True)
    dex_dir.mkdir(parents=True, exist_ok=True)

    java_files: list[str] = []
    for rel_path, content in sources.items():
        dest = src_dir / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content.strip() + "\n", encoding="utf-8")
        java_files.append(str(dest))

    subprocess.run(
        [_find_javac(), "--release", "17", "-d", str(cls_dir), *java_files],
        check=True,
        capture_output=True,
        text=True,
    )
    class_files = [str(p) for p in sorted(cls_dir.rglob("*.class"))]
    subprocess.run(
        [str(d8), "--min-api", "26", "--output", str(dex_dir), *class_files],
        check=True,
        capture_output=True,
        text=True,
    )
    return dex_dir / "classes.dex"


def _verify_dex_with_d8(dex_or_mpe: Path, d8: Path, scratch_dir: Path) -> None:
    dex_copy = scratch_dir / f"verify_{dex_or_mpe.stem}.dex"
    out_dir = scratch_dir / f"d8_out_{dex_or_mpe.stem}"
    out_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(dex_or_mpe, dex_copy)
    res = subprocess.run(
        [str(d8), "--min-api", "26", "--output", str(out_dir), str(dex_copy)],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        raise AssertionError(f"d8 verification failed for {dex_or_mpe}:\n{res.stdout}\n{res.stderr}")


class BytecodeRewriterTests(unittest.TestCase):
    _tmp_ctx: tempfile.TemporaryDirectory[str]
    work_dir: Path
    d8: Path
    cli_jar: Path
    harness_cls_dir: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp_ctx = tempfile.TemporaryDirectory(prefix="morphe_rewriter_test_")
        cls.work_dir = Path(cls._tmp_ctx.name)
        cls.d8 = _find_d8()
        cls.cli_jar = _build_rewriter_jar(cls.work_dir)
        cls.harness_cls_dir = cls.work_dir / "harness_cls"
        cls.harness_cls_dir.mkdir(parents=True, exist_ok=True)
        harness_src = cls.work_dir / "DexVerifierHarness.java"
        harness_src.write_text(_DEX_VERIFIER_HARNESS_JAVA.strip() + "\n", encoding="utf-8")
        subprocess.run(
            [
                _find_javac(),
                "--release",
                "17",
                "-cp",
                str(cls.cli_jar),
                "-d",
                str(cls.harness_cls_dir),
                str(harness_src),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp_ctx.cleanup()

    def _run_harness(self, mode: str, dex_path: Path) -> None:
        cp = f"{self.harness_cls_dir}{os.pathsep}{self.cli_jar}"
        res = subprocess.run(
            [_java_bin(), "-cp", cp, "DexVerifierHarness", mode, str(dex_path)],
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            self.fail(f"DexVerifierHarness ({mode}) failed:\n{res.stdout}\n{res.stderr}")

    def test_standalone_shared_youtube_mpe_rewrite_and_execution(self) -> None:
        sub = self.work_dir / "shared_yt_case"
        sub.mkdir(parents=True, exist_ok=True)
        raw_dex = _compile_sources_to_dex(
            sub,
            "syt",
            {
                "app/morphe/extension/shared/spoof/ClientType.java": _CLIENT_TYPE_JAVA,
                "app/morphe/extension/shared/patches/AppCheckPatch.java": _SHARED_STUBS_JAVA,
                "app/morphe/extension/shared/spoof/potoken/PoTokenManager.java": _POTOKEN_MANAGER_JAVA,
                "app/morphe/extension/shared/patches/PoTokenProviderPatch.java": _POTOKEN_PROVIDER_PATCH_JAVA,
                "app/morphe/extension/shared/spoof/js/JavaScriptEngineSupport.java": _JS_SUPPORT_JAVA,
                "app/morphe/extension/shared/spoof/requests/StreamingDataRequest.java": _STREAMING_DATA_REQUEST_JAVA,
            },
            self.d8,
        )
        mpe_path = sub / "shared-youtube.mpe"
        shutil.copyfile(raw_dex, mpe_path)
        raw_bytes = mpe_path.read_bytes()

        patcher_mod._java_helper_path = None
        cli = PatcherCLI(self.cli_jar, {}, Path("bin/apksigner.jar"))
        cli.rewrite_mpe(mpe_path, "com.google.android.youtube")
        pass1_bytes = mpe_path.read_bytes()
        cli.rewrite_mpe(mpe_path, "com.google.android.youtube")
        pass2_bytes = mpe_path.read_bytes()

        self.assertNotEqual(raw_bytes, pass1_bytes)
        self.assertEqual(pass1_bytes, pass2_bytes)

        _verify_dex_with_d8(mpe_path, self.d8, sub)
        self._run_harness("shared-youtube", mpe_path)

    def test_rewrite_music_dex_handles_tv_simply_and_tv_sabr_inputs(self) -> None:
        for first_client in ("TV_SIMPLY", "TV_SABR"):
            with self.subTest(first_client=first_client):
                sub = self.work_dir / f"music_case_{first_client.lower()}"
                sub.mkdir(parents=True, exist_ok=True)
                raw_dex = _compile_sources_to_dex(
                    sub,
                    "music",
                    {
                        "app/morphe/extension/shared/spoof/ClientType.java": _CLIENT_TYPE_JAVA,
                        "app/morphe/extension/music/settings/Settings.java": _MUSIC_SETTINGS_JAVA,
                        "app/morphe/extension/music/patches/spoof/SpoofVideoStreamsPatch.java": _MUSIC_PATCH_TEMPLATE_JAVA.replace(
                            "__FIRST_CLIENT__", first_client
                        ),
                    },
                    self.d8,
                )
                mpe_path = sub / "music.mpe"
                shutil.copyfile(raw_dex, mpe_path)

                cli = PatcherCLI(self.cli_jar, {}, Path("bin/apksigner.jar"))
                cli.rewrite_mpe(mpe_path, "com.google.android.apps.youtube.music")
                cli.rewrite_mpe(mpe_path, "com.google.android.apps.youtube.music")

                _verify_dex_with_d8(mpe_path, self.d8, sub)
                self._run_harness("music", mpe_path)

    def test_rewrite_youtube_dex_replaces_tv_simply_with_tv_sabr(self) -> None:
        sub = self.work_dir / "youtube_case"
        sub.mkdir(parents=True, exist_ok=True)
        raw_dex = _compile_sources_to_dex(
            sub,
            "yt",
            {
                "app/morphe/extension/shared/spoof/ClientType.java": _CLIENT_TYPE_JAVA,
                "app/morphe/extension/youtube/settings/Settings.java": _YT_SETTINGS_JAVA,
                "app/morphe/extension/youtube/patches/spoof/SpoofVideoStreamsPatch.java": _YT_PATCH_JAVA,
            },
            self.d8,
        )
        mpe_path = sub / "youtube.mpe"
        shutil.copyfile(raw_dex, mpe_path)

        cli = PatcherCLI(self.cli_jar, {}, Path("bin/apksigner.jar"))
        cli.rewrite_mpe(mpe_path, "com.google.android.youtube")

        _verify_dex_with_d8(mpe_path, self.d8, sub)
        self._run_harness("youtube", mpe_path)

    def test_helper_java_uses_v8_cache_dir(self) -> None:
        patcher_mod._java_helper_path = None
        helper = _ensure_helper_java()
        self.assertEqual(helper.parent.name, "morphe_ext_rewriter_v8")
        self.assertTrue(helper.is_file())

    def test_ensure_mpp_compatibility_invalidates_on_mpp_or_helper_mtime(self) -> None:
        sub = self.work_dir / "cache_invalidation_case"
        sub.mkdir(parents=True, exist_ok=True)
        mpp_path = sub / "patches-2.3.0.mpp"
        with zipfile.ZipFile(mpp_path, "w") as zf:
            zf.writestr("extensions/shared-youtube.mpe", b"dex-placeholder")
            zf.writestr("extensions/youtube.mpe", b"dex-placeholder")

        helper_file = sub / "FakeHelper.java"
        helper_file.write_text("// helper", encoding="utf-8")
        base_time = 1_700_000_000.0
        os.utime(mpp_path, (base_time, base_time))
        os.utime(helper_file, (base_time, base_time))

        pkg = "com.google.android.youtube"
        rewritten_expected = sub / f"patches-2.3.0-{pkg}.mpp"

        with (
            mock.patch.object(patcher_mod, "_ensure_helper_java", return_value=helper_file),
            mock.patch.object(PatcherCLI, "_run_rewriter") as mock_run,
        ):
            def touch_rewritten(target: Path, _pkg: str = "") -> None:
                os.utime(target, (base_time + 10.0, base_time + 10.0))

            mock_run.side_effect = touch_rewritten

            # 1. Initial call rewrites because target compat MPP does not exist yet.
            cli1 = PatcherCLI(self.cli_jar, {("morphe", "2.3.0"): mpp_path}, Path("bin/apksigner.jar"))
            cli1.ensure_mpp_compatibility(pkg)
            self.assertEqual(mock_run.call_count, 1)
            self.assertEqual(cli1.mpp_map[("morphe", "2.3.0")], rewritten_expected.resolve())

            # 2. Fresh CLI instance reuses cached compat MPP when both mtimes are older.
            cli2 = PatcherCLI(self.cli_jar, {("morphe", "2.3.0"): mpp_path}, Path("bin/apksigner.jar"))
            cli2.ensure_mpp_compatibility(pkg)
            self.assertEqual(mock_run.call_count, 1)

            # 3. Advancing helper_java mtime invalidates stale compat MPP.
            os.utime(helper_file, (base_time + 20.0, base_time + 20.0))

            def touch_rewritten_v2(target: Path, _pkg: str = "") -> None:
                os.utime(target, (base_time + 30.0, base_time + 30.0))

            mock_run.side_effect = touch_rewritten_v2
            cli3 = PatcherCLI(self.cli_jar, {("morphe", "2.3.0"): mpp_path}, Path("bin/apksigner.jar"))
            cli3.ensure_mpp_compatibility(pkg)
            self.assertEqual(mock_run.call_count, 2)

            # 4. Advancing source mpp mtime also invalidates cached compat MPP.
            os.utime(mpp_path, (base_time + 40.0, base_time + 40.0))
            cli4 = PatcherCLI(self.cli_jar, {("morphe", "2.3.0"): mpp_path}, Path("bin/apksigner.jar"))
            cli4.ensure_mpp_compatibility(pkg)
            self.assertEqual(mock_run.call_count, 3)


if __name__ == "__main__":
    unittest.main()
