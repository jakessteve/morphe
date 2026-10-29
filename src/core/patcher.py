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

import contextlib
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

from src.core.config import PatchSpec
from src.core.logger import pr, wpr
from src.core.prebuilts import get_highest_ver

_SECRET_PATTERNS = re.compile(r"(keystore-password=|keystore-entry-password=)\S+")
_java_bin_cached: str | None = None
_java_helper_path: Path | None = None

_REWRITER_JAVA_SOURCE = r"""
import com.android.tools.smali.dexlib2.DexFileFactory;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21c;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction35c;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction3rc;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.DexFile;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction;
import com.android.tools.smali.dexlib2.iface.reference.FieldReference;
import com.android.tools.smali.dexlib2.iface.reference.MethodReference;
import com.android.tools.smali.dexlib2.iface.reference.StringReference;
import com.android.tools.smali.dexlib2.iface.reference.TypeReference;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableFieldReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableTypeReference;
import com.android.tools.smali.dexlib2.rewriter.DexRewriter;
import com.android.tools.smali.dexlib2.rewriter.MethodRewriter;
import com.android.tools.smali.dexlib2.rewriter.Rewriter;
import com.android.tools.smali.dexlib2.rewriter.RewriterModule;
import com.android.tools.smali.dexlib2.rewriter.Rewriters;
import com.android.tools.smali.smali.Smali;
import com.android.tools.smali.smali.SmaliOptions;
import java.io.*;
import java.net.URI;
import java.nio.file.*;
import java.security.*;
import java.security.cert.Certificate;
import java.util.*;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class MppExtensionRewriter {
    private static final String SIGCOMP_SMALI_SOURCE =
        ".class public Lapp/morphe/extension/facebook/SignatureCompatibility;\n" +
        ".super Ljava/lang/Object;\n\n" +
        ".method public static hookMessengerIntent(Landroid/content/Intent;)Landroid/content/Intent;\n" +
        "    .registers 8\n" +
        "    .param p0, \"intent\"\n\n" +
        "    if-nez p0, :cond_has_intent\n" +
        "    return-object p0\n\n" +
        ":cond_has_intent\n" +
        "    invoke-virtual {p0}, Landroid/content/Intent;->getComponent()Landroid/content/ComponentName;\n" +
        "    move-result-object v0\n" +
        "    if-nez v0, :cond_has_comp\n" +
        "    goto :cond_proceed\n\n" +
        ":cond_has_comp\n" +
        "    return-object p0\n\n" +
        ":cond_proceed\n" +
        "    invoke-virtual {p0}, Landroid/content/Intent;->getData()Landroid/net/Uri;\n" +
        "    move-result-object v1\n" +
        "    if-nez v1, :cond_has_data\n" +
        "    return-object p0\n\n" +
        ":cond_has_data\n" +
        "    invoke-virtual {v1}, Landroid/net/Uri;->getScheme()Ljava/lang/String;\n" +
        "    move-result-object v1\n" +
        "    if-nez v1, :cond_check_scheme\n" +
        "    return-object p0\n\n" +
        ":cond_check_scheme\n" +
        "    const-string v3, \"fb-messenger\"\n" +
        "    invoke-virtual {v3, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n" +
        "    move-result v3\n" +
        "    if-nez v3, :cond_matched\n\n" +
        "    const-string v3, \"fb-messenger-secure\"\n" +
        "    invoke-virtual {v3, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n" +
        "    move-result v3\n" +
        "    if-nez v3, :cond_matched\n\n" +
        "    const-string v3, \"fb-messenger-sametask\"\n" +
        "    invoke-virtual {v3, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n" +
        "    move-result v3\n" +
        "    if-nez v3, :cond_matched\n\n" +
        "    const-string v3, \"fb-messenger-family\"\n" +
        "    invoke-virtual {v3, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n" +
        "    move-result v3\n" +
        "    if-nez v3, :cond_matched\n\n" +
        "    return-object p0\n\n" +
        ":cond_matched\n" +
        "    invoke-virtual {p0}, Landroid/content/Intent;->getAction()Ljava/lang/String;\n" +
        "    move-result-object v2\n\n" +
        ":cond_check_secure\n" +
        "    const-string v3, \"fb-messenger-secure\"\n" +
        "    invoke-virtual {v3, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n" +
        "    move-result v3\n" +
        "    if-eqz v3, :cond_check_sametask\n" +
        "    const-string v1, \"com.facebook.messenger.intents.SecureIntentHandlerActivity\"\n" +
        "    goto :goto_set_comp\n\n" +
        ":cond_check_sametask\n" +
        "    const-string v3, \"fb-messenger-sametask\"\n" +
        "    invoke-virtual {v3, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n" +
        "    move-result v3\n" +
        "    if-eqz v3, :cond_check_family\n" +
        "    const-string v3, \"com.facebook.orca.notify.SECURE_VIEW\"\n" +
        "    invoke-virtual {v3, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n" +
        "    move-result v3\n" +
        "    if-nez v3, :cond_sametask_sec\n" +
        "    const-string v3, \"android.intent.action.SENDTO\"\n" +
        "    invoke-virtual {v3, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n" +
        "    move-result v3\n" +
        "    if-nez v3, :cond_sametask_sec\n" +
        "    const-string v1, \"com.facebook.messenger.intents.SameTaskIntentHandlerActivity\"\n" +
        "    goto :goto_set_comp\n" +
        ":cond_sametask_sec\n" +
        "    const-string v1, \"com.facebook.messenger.intents.SecureSameTaskIntentHandlerActivity\"\n" +
        "    goto :goto_set_comp\n\n" +
        ":cond_check_family\n" +
        "    const-string v3, \"fb-messenger-family\"\n" +
        "    invoke-virtual {v3, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n" +
        "    move-result v3\n" +
        "    if-eqz v3, :cond_check_fbmessenger\n" +
        "    const-string v1, \"com.facebook.messenger.intents.FamilyIntentHandlerActivity\"\n" +
        "    goto :goto_set_comp\n\n" +
        ":cond_check_fbmessenger\n" +
        "    const-string v3, \"fb-messenger\"\n" +
        "    invoke-virtual {v3, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n" +
        "    move-result v3\n" +
        "    if-eqz v3, :cond_default_target\n" +
        "    if-eqz v2, :cond_default_target\n" +
        "    const-string v3, \"android.intent.action.VIEW\"\n" +
        "    invoke-virtual {v3, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n" +
        "    move-result v3\n" +
        "    if-nez v3, :cond_default_target\n" +
        "    const-string v3, \"android.nfc.action.NDEF_DISCOVERED\"\n" +
        "    invoke-virtual {v3, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n" +
        "    move-result v3\n" +
        "    if-nez v3, :cond_default_target\n" +
        "    const-string v1, \"com.facebook.messenger.intents.SecureIntentHandlerActivity\"\n" +
        "    goto :goto_set_comp\n\n" +
        ":cond_default_target\n" +
        "    const-string v1, \"com.facebook.messenger.intents.IntentHandlerActivity\"\n\n" +
        ":goto_set_comp\n" +
        "    const-string v2, \"com.facebook.orca\"\n" +
        "    invoke-virtual {p0, v2}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;\n" +
        "    new-instance v3, Landroid/content/ComponentName;\n" +
        "    invoke-direct {v3, v2, v1}, Landroid/content/ComponentName;-><init>(Ljava/lang/String;Ljava/lang/String;)V\n" +
        "    invoke-virtual {p0, v3}, Landroid/content/Intent;->setComponent(Landroid/content/ComponentName;)Landroid/content/Intent;\n" +
        "    return-object p0\n" +
        ".end method\n\n" +
        ".method public static setPackage(Landroid/content/Intent;Ljava/lang/String;)Landroid/content/Intent;\n" +
        "    .registers 2\n" +
        "    .param p0, \"intent\"\n" +
        "    .param p1, \"pkg\"\n\n" +
        "    if-nez p0, :cond_null\n" +
        "    const/4 v0, 0x0\n" +
        "    return-object v0\n\n" +
        ":cond_null\n" +
        "    invoke-virtual {p0, p1}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;\n" +
        "    invoke-static {p0}, Lapp/morphe/extension/facebook/SignatureCompatibility;->hookMessengerIntent(Landroid/content/Intent;)Landroid/content/Intent;\n" +
        "    move-result-object v0\n" +
        "    return-object v0\n" +
        ".end method\n\n" +
        ".method public static queryIntentActivities(Landroid/content/pm/PackageManager;Landroid/content/Intent;I)Ljava/util/List;\n" +
        "    .registers 4\n" +
        "    .param p0, \"pm\"\n" +
        "    .param p1, \"intent\"\n" +
        "    .param p2, \"flags\"\n\n" +
        "    invoke-static {p1}, Lapp/morphe/extension/facebook/SignatureCompatibility;->hookMessengerIntent(Landroid/content/Intent;)Landroid/content/Intent;\n" +
        "    invoke-virtual {p0, p1, p2}, Landroid/content/pm/PackageManager;->queryIntentActivities(Landroid/content/Intent;I)Ljava/util/List;\n" +
        "    move-result-object v0\n" +
        "    return-object v0\n" +
        ".end method\n\n" +
        ".method public static startActivity(Landroid/content/Context;Landroid/content/Intent;)V\n" +
        "    .registers 2\n" +
        "    .param p0, \"ctx\"\n" +
        "    .param p1, \"intent\"\n\n" +
        "    invoke-static {p1}, Lapp/morphe/extension/facebook/SignatureCompatibility;->hookMessengerIntent(Landroid/content/Intent;)Landroid/content/Intent;\n" +
        "    invoke-virtual {p0, p1}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V\n" +
        "    return-void\n" +
        ".end method\n\n" +
        ".method public static startActivity(Landroid/content/Context;Landroid/content/Intent;Landroid/os/Bundle;)V\n" +
        "    .registers 3\n" +
        "    .param p0, \"ctx\"\n" +
        "    .param p1, \"intent\"\n" +
        "    .param p2, \"options\"\n\n" +
        "    invoke-static {p1}, Lapp/morphe/extension/facebook/SignatureCompatibility;->hookMessengerIntent(Landroid/content/Intent;)Landroid/content/Intent;\n" +
        "    invoke-virtual {p0, p1, p2}, Landroid/content/Context;->startActivity(Landroid/content/Intent;Landroid/os/Bundle;)V\n" +
        "    return-void\n" +
        ".end method\n\n" +
        ".method public static startActivityForResult(Landroid/app/Activity;Landroid/content/Intent;I)V\n" +
        "    .registers 3\n" +
        "    .param p0, \"act\"\n" +
        "    .param p1, \"intent\"\n" +
        "    .param p2, \"requestCode\"\n\n" +
        "    invoke-static {p1}, Lapp/morphe/extension/facebook/SignatureCompatibility;->hookMessengerIntent(Landroid/content/Intent;)Landroid/content/Intent;\n" +
        "    invoke-virtual {p0, p1, p2}, Landroid/app/Activity;->startActivityForResult(Landroid/content/Intent;I)V\n" +
        "    return-void\n" +
        ".end method\n\n" +
        ".method public static startActivityForResult(Landroid/app/Activity;Landroid/content/Intent;ILandroid/os/Bundle;)V\n" +
        "    .registers 4\n" +
        "    .param p0, \"act\"\n" +
        "    .param p1, \"intent\"\n" +
        "    .param p2, \"requestCode\"\n" +
        "    .param p3, \"options\"\n\n" +
        "    invoke-static {p1}, Lapp/morphe/extension/facebook/SignatureCompatibility;->hookMessengerIntent(Landroid/content/Intent;)Landroid/content/Intent;\n" +
        "    invoke-virtual {p0, p1, p2, p3}, Landroid/app/Activity;->startActivityForResult(Landroid/content/Intent;ILandroid/os/Bundle;)V\n" +
        "    return-void\n" +
        ".end method\n";

    private static final String FB_SIG_PATCH_SOURCE =
        "package app.morphe.patches.facebook.misc;\n\n" +
        "import app.morphe.patcher.extensions.InstructionExtensions;\n" +
        "import app.morphe.patcher.patch.*;\n" +
        "import app.morphe.patches.facebook.shared.Constants;\n" +
        "import app.morphe.patches.shared.misc.extension.ExtensionHook;\n" +
        "import app.morphe.patches.shared.misc.extension.SharedExtensionPatchKt;\n" +
        "import app.morphe.util.BytecodeUtilsKt;\n" +
        "import com.android.tools.smali.dexlib2.Opcode;\n" +
        "import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction35c;\n" +
        "import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction3rc;\n" +
        "import com.android.tools.smali.dexlib2.iface.ClassDef;\n" +
        "import com.android.tools.smali.dexlib2.iface.Method;\n" +
        "import com.android.tools.smali.dexlib2.iface.MethodImplementation;\n" +
        "import com.android.tools.smali.dexlib2.iface.instruction.Instruction;\n" +
        "import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction;\n" +
        "import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction;\n" +
        "import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction35c;\n" +
        "import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction3rc;\n" +
        "import com.android.tools.smali.dexlib2.iface.reference.MethodReference;\n" +
        "import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference;\n" +
        "import kotlin.Unit;\n" +
        "import java.util.*;\n" +
        "import java.util.concurrent.atomic.AtomicInteger;\n\n" +
        "public final class SignatureCompatibilityPatchKt {\n" +
        "    private static final BytecodePatch extensionPatch =\n" +
        "        SharedExtensionPatchKt.sharedExtensionPatch(\"facebook\", false, new ExtensionHook[0]);\n\n" +
        "    private static final BytecodePatch signatureCompatibilityPatch =\n" +
        "        PatchKt.bytecodePatch(\n" +
        "            \"Facebook signature compatibility\",\n" +
        "            \"Keeps Facebook first-party navigation working after signing with the established De-Vanced key.\",\n" +
        "            true,\n" +
        "            builder -> {\n" +
        "                builder.compatibleWith(Constants.INSTANCE.getCOMPATIBILITY());\n" +
        "                builder.dependsOn(extensionPatch);\n" +
        "                builder.execute(context -> {\n" +
        "                    AtomicInteger sigHookCount = new AtomicInteger(0);\n" +
        "                    AtomicInteger intentHookCount = new AtomicInteger(0);\n\n" +
        "                    context.classDefForEach(classDef -> {\n" +
        "                        String classType = classDef.getType();\n" +
        "                        if (classType.startsWith(\"Lapp/morphe/extension/\")) {\n" +
        "                            return Unit.INSTANCE;\n" +
        "                        }\n\n" +
        "                        app.morphe.patcher.util.proxy.mutableTypes.MutableClass mutableClass = null;\n\n" +
        "                        for (Method m : classDef.getMethods()) {\n" +
        "                            MethodImplementation mi = m.getImplementation();\n" +
        "                            if (mi == null) continue;\n\n" +
        "                            List<Instruction> instructions = new ArrayList<>();\n" +
        "                            for (Instruction ins : mi.getInstructions()) {\n" +
        "                                instructions.add(ins);\n" +
        "                            }\n\n" +
        "                            app.morphe.patcher.util.proxy.mutableTypes.MutableMethod mutableMethod = null;\n\n" +
        "                            for (int idx = instructions.size() - 1; idx >= 0; idx--) {\n" +
        "                                Instruction ins = instructions.get(idx);\n" +
        "                                if (ins instanceof ReferenceInstruction) {\n" +
        "                                    var ref = ((ReferenceInstruction) ins).getReference();\n" +
        "                                    if (ref instanceof MethodReference) {\n" +
        "                                        MethodReference mr = (MethodReference) ref;\n" +
        "                                        if (\"Landroid/content/pm/Signature;\".equals(mr.getDefiningClass())\n" +
        "                                            && \"toByteArray\".equals(mr.getName())\n" +
        "                                            && \"[B\".equals(mr.getReturnType())\n" +
        "                                            && mr.getParameterTypes().isEmpty()) {\n\n" +
        "                                            if (idx + 1 >= instructions.size()) {\n" +
        "                                                throw new IllegalStateException(\"Signature.toByteArray is not followed by move-result-object in \" + m);\n" +
        "                                            }\n" +
        "                                            Instruction nextIns = instructions.get(idx + 1);\n" +
        "                                            if (nextIns.getOpcode() != Opcode.MOVE_RESULT_OBJECT || !(nextIns instanceof OneRegisterInstruction)) {\n" +
        "                                                throw new IllegalStateException(\"Signature.toByteArray is not followed by move-result-object in \" + m);\n" +
        "                                            }\n\n" +
        "                                            int reg = ((OneRegisterInstruction) nextIns).getRegisterA();\n" +
        "                                            if (mutableClass == null) {\n" +
        "                                                mutableClass = context.mutableClassDefBy(classDef);\n" +
        "                                            }\n" +
        "                                            if (mutableMethod == null) {\n" +
        "                                                mutableMethod = BytecodeUtilsKt.findMutableMethodOf(mutableClass, m);\n" +
        "                                            }\n\n" +
        "                                            String hookSmali =\n" +
        "                                                \"invoke-static/range {v\" + reg + \" .. v\" + reg + \"}, Lapp/morphe/extension/facebook/SignatureCompatibility;->spoofSignatureBytes([B)[B\\n\" +\n" +
        "                                                \"move-result-object v\" + reg;\n\n" +
        "                                            InstructionExtensions.INSTANCE.addInstructions(mutableMethod, idx + 2, hookSmali);\n" +
        "                                            sigHookCount.incrementAndGet();\n" +
        "                                        }\n" +
        "                                    }\n" +
        "                                }\n" +
        "                            }\n\n" +
        "                            for (int idx = 0; idx < instructions.size(); idx++) {\n" +
        "                                Instruction ins = instructions.get(idx);\n" +
        "                                Opcode op = ins.getOpcode();\n" +
        "                                boolean is35c = (op == Opcode.INVOKE_VIRTUAL);\n" +
        "                                boolean is3rc = (op == Opcode.INVOKE_VIRTUAL_RANGE);\n" +
        "                                if (!is35c && !is3rc) continue;\n\n" +
        "                                if (!(ins instanceof ReferenceInstruction)) continue;\n" +
        "                                var ref = ((ReferenceInstruction) ins).getReference();\n" +
        "                                if (!(ref instanceof MethodReference)) continue;\n" +
        "                                MethodReference mr = (MethodReference) ref;\n\n" +
        "                                String targetName = null;\n" +
        "                                List<String> targetParams = null;\n" +
        "                                String targetRet = null;\n\n" +
        "                                String defClass = mr.getDefiningClass();\n" +
        "                                String mName = mr.getName();\n" +
        "                                List<? extends CharSequence> pTypes = mr.getParameterTypes();\n" +
        "                                int pCount = pTypes.size();\n\n" +
        "                                if (\"setPackage\".equals(mName) && pCount == 1 && \"Landroid/content/Intent;\".equals(defClass)) {\n" +
        "                                    if (\"Ljava/lang/String;\".equals(pTypes.get(0).toString())) {\n" +
        "                                        targetName = \"setPackage\";\n" +
        "                                        targetParams = List.of(\"Landroid/content/Intent;\", \"Ljava/lang/String;\");\n" +
        "                                        targetRet = \"Landroid/content/Intent;\";\n" +
        "                                    }\n" +
        "                                } else if (\"queryIntentActivities\".equals(mName) && pCount == 2\n" +
        "                                    && (\"Landroid/content/pm/PackageManager;\".equals(defClass) || \"Landroid/app/ApplicationPackageManager;\".equals(defClass))) {\n" +
        "                                    if (\"Landroid/content/Intent;\".equals(pTypes.get(0).toString()) && \"I\".equals(pTypes.get(1).toString())) {\n" +
        "                                        targetName = \"queryIntentActivities\";\n" +
        "                                        targetParams = List.of(\"Landroid/content/pm/PackageManager;\", \"Landroid/content/Intent;\", \"I\");\n" +
        "                                        targetRet = \"Ljava/util/List;\";\n" +
        "                                    }\n" +
        "                                } else if (\"startActivity\".equals(mName)\n" +
        "                                    && (\"Landroid/content/Context;\".equals(defClass) || \"Landroid/app/Activity;\".equals(defClass) || \"Landroid/content/ContextWrapper;\".equals(defClass))) {\n" +
        "                                    if (pCount == 1 && \"Landroid/content/Intent;\".equals(pTypes.get(0).toString())) {\n" +
        "                                        targetName = \"startActivity\";\n" +
        "                                        targetParams = List.of(\"Landroid/content/Context;\", \"Landroid/content/Intent;\");\n" +
        "                                        targetRet = \"V\";\n" +
        "                                    } else if (pCount == 2 && \"Landroid/content/Intent;\".equals(pTypes.get(0).toString()) && \"Landroid/os/Bundle;\".equals(pTypes.get(1).toString())) {\n" +
        "                                        targetName = \"startActivity\";\n" +
        "                                        targetParams = List.of(\"Landroid/content/Context;\", \"Landroid/content/Intent;\", \"Landroid/os/Bundle;\");\n" +
        "                                        targetRet = \"V\";\n" +
        "                                    }\n" +
        "                                } else if (\"startActivityForResult\".equals(mName)\n" +
        "                                    && (\"Landroid/app/Activity;\".equals(defClass) || \"Landroid/content/Context;\".equals(defClass))) {\n" +
        "                                    if (pCount == 2 && \"Landroid/content/Intent;\".equals(pTypes.get(0).toString()) && \"I\".equals(pTypes.get(1).toString())) {\n" +
        "                                        targetName = \"startActivityForResult\";\n" +
        "                                        targetParams = List.of(\"Landroid/app/Activity;\", \"Landroid/content/Intent;\", \"I\");\n" +
        "                                        targetRet = \"V\";\n" +
        "                                    } else if (pCount == 3 && \"Landroid/content/Intent;\".equals(pTypes.get(0).toString()) && \"I\".equals(pTypes.get(1).toString()) && \"Landroid/os/Bundle;\".equals(pTypes.get(2).toString())) {\n" +
        "                                        targetName = \"startActivityForResult\";\n" +
        "                                        targetParams = List.of(\"Landroid/app/Activity;\", \"Landroid/content/Intent;\", \"I\", \"Landroid/os/Bundle;\");\n" +
        "                                        targetRet = \"V\";\n" +
        "                                    }\n" +
        "                                }\n\n" +
        "                                if (targetName != null) {\n" +
        "                                    if (mutableClass == null) {\n" +
        "                                        mutableClass = context.mutableClassDefBy(classDef);\n" +
        "                                    }\n" +
        "                                    if (mutableMethod == null) {\n" +
        "                                        mutableMethod = BytecodeUtilsKt.findMutableMethodOf(mutableClass, m);\n" +
        "                                    }\n\n" +
        "                                    var methodRef = new ImmutableMethodReference(\n" +
        "                                        \"Lapp/morphe/extension/facebook/SignatureCompatibility;\",\n" +
        "                                        targetName,\n" +
        "                                        targetParams,\n" +
        "                                        targetRet\n" +
        "                                    );\n\n" +
        "                                    if (is35c) {\n" +
        "                                        Instruction35c i35 = (Instruction35c) ins;\n" +
        "                                        var newIns = new BuilderInstruction35c(\n" +
        "                                            Opcode.INVOKE_STATIC,\n" +
        "                                            i35.getRegisterCount(),\n" +
        "                                            i35.getRegisterC(),\n" +
        "                                            i35.getRegisterD(),\n" +
        "                                            i35.getRegisterE(),\n" +
        "                                            i35.getRegisterF(),\n" +
        "                                            i35.getRegisterG(),\n" +
        "                                            methodRef\n" +
        "                                        );\n" +
        "                                        InstructionExtensions.INSTANCE.replaceInstruction(mutableMethod, idx, newIns);\n" +
        "                                    } else {\n" +
        "                                        Instruction3rc i3r = (Instruction3rc) ins;\n" +
        "                                        var newIns = new BuilderInstruction3rc(\n" +
        "                                            Opcode.INVOKE_STATIC_RANGE,\n" +
        "                                            i3r.getStartRegister(),\n" +
        "                                            i3r.getRegisterCount(),\n" +
        "                                            methodRef\n" +
        "                                        );\n" +
        "                                        InstructionExtensions.INSTANCE.replaceInstruction(mutableMethod, idx, newIns);\n" +
        "                                    }\n" +
        "                                    intentHookCount.incrementAndGet();\n" +
        "                                }\n" +
        "                            }\n" +
        "                        }\n" +
        "                        return Unit.INSTANCE;\n" +
        "                    });\n\n" +
        "                    if (sigHookCount.get() <= 0) {\n" +
        "                        throw new IllegalStateException(\"No Facebook Signature.toByteArray consumers were found\");\n" +
        "                    }\n" +
        "                    System.out.println(\"[SignatureCompatibility] signatureByteHooks=\" + sigHookCount.get() + \", intentHooks=\" + intentHookCount.get());\n" +
        "                    return Unit.INSTANCE;\n" +
        "                });\n" +
        "                return Unit.INSTANCE;\n" +
        "            }\n" +
        "        );\n\n" +
        "    public static BytecodePatch getSignatureCompatibilityPatch() {\n" +
        "        return signatureCompatibilityPatch;\n" +
        "    }\n" +
        "}\n";

    public static String getKeystoreCertHash(String ksPath, String ksPass, String ksAlias) {
        if (ksPath == null || ksPath.isEmpty() || !new File(ksPath).exists()) {
            return "5LFsJbuQHSK1EAX9_g6Bb2NmwwZlcxrCqfnsjk1OWI4";
        }
        Security.addProvider(new BouncyCastleProvider());
        String[] types = {"BKS", "PKCS12", "JKS"};
        char[] pass = (ksPass != null && !ksPass.isEmpty()) ? ksPass.toCharArray() : "".toCharArray();
        for (String t : types) {
            try {
                KeyStore ks = KeyStore.getInstance(t);
                try (FileInputStream fis = new FileInputStream(ksPath)) {
                    ks.load(fis, pass);
                }
                String alias = ksAlias;
                if (alias == null || alias.isEmpty() || !ks.containsAlias(alias)) {
                    var aliases = ks.aliases();
                    if (aliases.hasMoreElements()) {
                        alias = aliases.nextElement();
                    }
                }
                if (alias != null && ks.containsAlias(alias)) {
                    Certificate cert = ks.getCertificate(alias);
                    if (cert != null) {
                        MessageDigest md = MessageDigest.getInstance("SHA-256");
                        byte[] digest = md.digest(cert.getEncoded());
                        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
                    }
                }
            } catch (Exception ignored) {
            }
        }
        return "5LFsJbuQHSK1EAX9_g6Bb2NmwwZlcxrCqfnsjk1OWI4";
    }

    private static String findD8() {
        try {
            Process p = new ProcessBuilder("which", "d8").redirectErrorStream(true).start();
            if (p.waitFor() == 0) {
                String out = new String(p.getInputStream().readAllBytes()).trim();
                if (!out.isEmpty() && new File(out).canExecute()) return out;
            }
        } catch (Exception ignored) {}

        String androidHome = System.getenv("ANDROID_HOME");
        if (androidHome == null || androidHome.isEmpty()) {
            androidHome = System.getenv("ANDROID_SDK_ROOT");
        }
        List<File> candidates = new ArrayList<>();
        if (androidHome != null && !androidHome.isEmpty()) {
            File bt = new File(androidHome, "build-tools");
            if (bt.isDirectory()) {
                File[] subs = bt.listFiles();
                if (subs != null) candidates.addAll(Arrays.asList(subs));
            }
        }
        File defaultSdkBt = new File(System.getProperty("user.home"), "Android/Sdk/build-tools");
        if (defaultSdkBt.isDirectory()) {
            File[] subs = defaultSdkBt.listFiles();
            if (subs != null) candidates.addAll(Arrays.asList(subs));
        }
        candidates.sort((a, b) -> b.getName().compareTo(a.getName()));
        for (File f : candidates) {
            File exe = new File(f, "d8");
            if (exe.isFile() && exe.canExecute()) return exe.getAbsolutePath();
        }
        return null;
    }

    private static void deleteRecursively(Path p) {
        if (Files.isDirectory(p)) {
            try (var stream = Files.walk(p)) {
                stream.sorted(Comparator.reverseOrder()).forEach(path -> {
                    try { Files.deleteIfExists(path); } catch (Exception ignored) {}
                });
            } catch (Exception ignored) {}
        } else {
            try { Files.deleteIfExists(p); } catch (Exception ignored) {}
        }
    }

    public static void rewriteFacebookDex(File inDex, File outDex, String ksSha256B64Url) throws Exception {
        DexFile dex = DexFileFactory.loadDexFile(inDex, Opcodes.getDefault());
        DexRewriter rewriter = new DexRewriter(new RewriterModule() {
            @Override
            public Rewriter<Instruction> getInstructionRewriter(Rewriters rewriters) {
                return new Rewriter<Instruction>() {
                    @Override
                    public Instruction rewrite(Instruction ins) {
                        if (ins instanceof ReferenceInstruction) {
                            var ref = ((ReferenceInstruction) ins).getReference();
                            if (ref instanceof StringReference) {
                                if ("Iu9BsdzR-Gl6uDxc5Ikj1JTG5yHP85puwCpFjZPZefw".equals(((StringReference) ref).getString())) {
                                    int reg = ((OneRegisterInstruction) ins).getRegisterA();
                                    return new BuilderInstruction21c(Opcode.CONST_STRING, reg, new ImmutableStringReference(ksSha256B64Url));
                                }
                            } else if (ins.getOpcode() == Opcode.SGET_OBJECT && ref instanceof FieldReference) {
                                FieldReference fr = (FieldReference) ref;
                                if ("OFFICIAL_CURRENT_CERTIFICATE".equals(fr.getName())) {
                                    int reg = ((OneRegisterInstruction) ins).getRegisterA();
                                    return new BuilderInstruction21c(
                                        Opcode.SGET_OBJECT,
                                        reg,
                                        new ImmutableFieldReference(fr.getDefiningClass(), "OFFICIAL_LEGACY_CERTIFICATE", fr.getType())
                                    );
                                }
                            }
                        }
                        return ins;
                    }
                };
            }
        });
        DexFile rewritten = rewriter.getDexFileRewriter().rewrite(dex);

        File smaliFile = File.createTempFile("sigcomp_hooks", ".smali");
        File helperDexFile = File.createTempFile("sigcomp_hooks", ".dex");
        ClassDef helperClass = null;
        try {
            Files.writeString(smaliFile.toPath(), SIGCOMP_SMALI_SOURCE);
            SmaliOptions opt = new SmaliOptions();
            opt.outputDexFile = helperDexFile.getAbsolutePath();
            opt.apiLevel = 26;
            if (Smali.assemble(opt, List.of(smaliFile.getAbsolutePath()))) {
                DexFile helperDex = DexFileFactory.loadDexFile(helperDexFile, Opcodes.getDefault());
                for (ClassDef item : helperDex.getClasses()) {
                    if ("Lapp/morphe/extension/facebook/SignatureCompatibility;".equals(item.getType())) {
                        helperClass = item;
                        break;
                    }
                }
            }
        } finally {
            smaliFile.delete();
            helperDexFile.delete();
        }

        Set<ClassDef> classes = new HashSet<>();
        for (ClassDef item : rewritten.getClasses()) {
            if ("Lapp/morphe/extension/facebook/SignatureCompatibility;".equals(item.getType())) {
                List<Method> combinedMethods = new ArrayList<>();
                Set<String> sigs = new HashSet<>();
                if (helperClass != null) {
                    for (Method m : helperClass.getMethods()) {
                        if (!m.getName().equals("<init>") && !m.getName().equals("<clinit>")) {
                            sigs.add(m.getName() + ":" + m.getParameters());
                            combinedMethods.add(m);
                        }
                    }
                }
                for (Method m : item.getMethods()) {
                    if (!sigs.contains(m.getName() + ":" + m.getParameters())) {
                        combinedMethods.add(m);
                    }
                }
                classes.add(new ImmutableClassDef(
                    item.getType(),
                    item.getAccessFlags(),
                    item.getSuperclass(),
                    item.getInterfaces(),
                    item.getSourceFile(),
                    item.getAnnotations(),
                    item.getFields(),
                    combinedMethods
                ));
            } else {
                classes.add(item);
            }
        }

        ImmutableDexFile finalDex = new ImmutableDexFile(Opcodes.getDefault(), classes);
        File tempOut = File.createTempFile("fb_rewrite", ".dex");
        try {
            DexFileFactory.writeDexFile(tempOut.getAbsolutePath(), finalDex);
            Files.copy(tempOut.toPath(), outDex.toPath(), StandardCopyOption.REPLACE_EXISTING);
        } finally {
            tempOut.delete();
        }
    }

    public static void rewriteExtensionDex(File inDex, File outDex) throws Exception {
        DexFile dex = DexFileFactory.loadDexFile(inDex, Opcodes.getDefault());
        DexRewriter rewriter = new DexRewriter(new RewriterModule() {
            @Override
            public Rewriter<Instruction> getInstructionRewriter(Rewriters rewriters) {
                return new Rewriter<Instruction>() {
                    @Override
                    public Instruction rewrite(Instruction ins) {
                        if (ins.getOpcode() == Opcode.CONST_CLASS && ins instanceof ReferenceInstruction) {
                            var ref = ((ReferenceInstruction) ins).getReference();
                            if (ref instanceof TypeReference && "Landroid/content/pm/PackageManager;".equals(((TypeReference) ref).getType())) {
                                int reg = ((OneRegisterInstruction) ins).getRegisterA();
                                return new BuilderInstruction21c(
                                    Opcode.CONST_CLASS,
                                    reg,
                                    new ImmutableTypeReference("Landroid/app/ApplicationPackageManager;")
                                );
                            }
                        } else if (ins instanceof ReferenceInstruction) {
                            var ref = ((ReferenceInstruction) ins).getReference();
                            if (ref instanceof StringReference) {
                                String s = ((StringReference) ref).getString();
                                if (s.contains("AMIHlR34")) {
                                    int reg = ((OneRegisterInstruction) ins).getRegisterA();
                                    return new BuilderInstruction21c(
                                        ins.getOpcode(),
                                        reg,
                                        new ImmutableStringReference(s.replace("AMIHlR34", "AMIH1R34"))
                                    );
                                }
                            }
                        }
                        return ins;
                    }
                };
            }

            @Override
            public Rewriter<Method> getMethodRewriter(Rewriters rewriters) {
                return new Rewriter<Method>() {
                    @Override
                    public Method rewrite(Method m) {
                        if ("Lapp/template/extension/extension/SignatureHookApp$1;".equals(m.getDefiningClass())
                            && "createFromParcel".equals(m.getName())
                            && "Landroid/content/pm/PackageInfo;".equals(m.getReturnType().toString())) {
                            MethodImplementation mi = m.getImplementation();
                            if (mi != null) {
                                List<Instruction> newIns = new ArrayList<>();
                                for (Instruction ins : mi.getInstructions()) {
                                    if (ins.getOpcode() == Opcode.IGET_OBJECT && ins instanceof ReferenceInstruction) {
                                        var ref = ((ReferenceInstruction) ins).getReference();
                                        if (ref instanceof FieldReference && "val$packageName".equals(((FieldReference) ref).getName())) {
                                            int regA = ((OneRegisterInstruction) ins).getRegisterA();
                                            newIns.add(new BuilderInstruction21c(Opcode.CONST_STRING, regA, new ImmutableStringReference("com.facebook.")));
                                            continue;
                                        }
                                    } else if (ins.getOpcode() == Opcode.INVOKE_VIRTUAL && ins instanceof ReferenceInstruction) {
                                        var ref = ((ReferenceInstruction) ins).getReference();
                                        if (ref instanceof MethodReference) {
                                            MethodReference mr = (MethodReference) ref;
                                            if ("Ljava/lang/String;".equals(mr.getDefiningClass()) && "equals".equals(mr.getName())) {
                                                newIns.add(new BuilderInstruction35c(
                                                    Opcode.INVOKE_VIRTUAL,
                                                    2, 0, 1, 0, 0, 0,
                                                    new ImmutableMethodReference(
                                                        "Ljava/lang/String;",
                                                        "startsWith",
                                                        List.of("Ljava/lang/String;"),
                                                        "Z"
                                                    )
                                                ));
                                                continue;
                                            }
                                        }
                                    }
                                    newIns.add(ins);
                                }
                                MethodImplementation newMi = new ImmutableMethodImplementation(
                                    mi.getRegisterCount(),
                                    newIns,
                                    mi.getTryBlocks(),
                                    mi.getDebugItems()
                                );
                                return new ImmutableMethod(
                                    m.getDefiningClass(),
                                    m.getName(),
                                    m.getParameters(),
                                    m.getReturnType(),
                                    m.getAccessFlags(),
                                    m.getAnnotations(),
                                    m.getHiddenApiRestrictions(),
                                    newMi
                                );
                            }
                        }
                        return new MethodRewriter(rewriters).rewrite(m);
                    }
                };
            }
        });
        DexFile rewritten = rewriter.getDexFileRewriter().rewrite(dex);
        File tempOut = File.createTempFile("ext_rewrite", ".dex");
        try {
            DexFileFactory.writeDexFile(tempOut.getAbsolutePath(), rewritten);
            Files.copy(tempOut.toPath(), outDex.toPath(), StandardCopyOption.REPLACE_EXISTING);
        } finally {
            tempOut.delete();
        }
    }

    private static void updateFacebookPatchClass(Path targetPath, FileSystem fs, Path fbPatchClassPath) {
        try {
            Path tempDir = Files.createTempDirectory("fb_sig_patch");
            try {
                Path srcFile = tempDir.resolve("SignatureCompatibilityPatchKt.java");
                Files.writeString(srcFile, FB_SIG_PATCH_SOURCE);

                String cliJar = System.getProperty("java.class.path");
                String cp = cliJar + File.pathSeparator + targetPath.toAbsolutePath().toString();

                JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
                boolean compiled = false;
                if (compiler != null) {
                    int res = compiler.run(null, null, null, "-cp", cp, "-d", tempDir.toString(), srcFile.toString());
                    compiled = (res == 0);
                }
                if (!compiled) {
                    String javaBin = ProcessHandle.current().info().command().orElse("java");
                    File javacBin = new File(new File(javaBin).getParentFile(), "javac");
                    String javacCmd = javacBin.exists() ? javacBin.getAbsolutePath() : "javac";
                    Process p = new ProcessBuilder(javacCmd, "-cp", cp, "-d", tempDir.toString(), srcFile.toString()).start();
                    compiled = (p.waitFor() == 0);
                }

                if (compiled) {
                    Path compiledClass = tempDir.resolve("app/morphe/patches/facebook/misc/SignatureCompatibilityPatchKt.class");
                    if (Files.exists(compiledClass)) {
                        Files.copy(compiledClass, fbPatchClassPath, StandardCopyOption.REPLACE_EXISTING);
                    }

                    Path cdexPath = fs.getPath("classes.dex");
                    if (Files.exists(cdexPath)) {
                        tryUpdateClassesDex(targetPath, fs, cdexPath, tempDir, compiledClass, cp);
                    }
                }
            } finally {
                deleteRecursively(tempDir);
            }
        } catch (Exception e) {
            System.err.println("Warning: failed to update Facebook patch bytecode: " + e.getMessage());
        }
    }

    private static void tryUpdateClassesDex(Path targetPath, FileSystem fs, Path cdexPath, Path tempDir, Path compiledClass, String cp) {
        try {
            String d8Bin = findD8();
            if (d8Bin == null) return;

            Path dexOutDir = tempDir.resolve("d8_out");
            Files.createDirectories(dexOutDir);

            String cliJar = System.getProperty("java.class.path");
            Process p = new ProcessBuilder(
                d8Bin, "--min-api", "26", "--output", dexOutDir.toString(),
                compiledClass.toString(),
                "--classpath", cliJar,
                "--classpath", targetPath.toAbsolutePath().toString()
            ).start();

            if (p.waitFor() == 0) {
                Path patchDex = dexOutDir.resolve("classes.dex");
                if (Files.exists(patchDex)) {
                    Path tempCdexIn = Files.createTempFile("cdex_in", ".dex");
                    Path tempCdexOut = Files.createTempFile("cdex_out", ".dex");
                    try {
                        Files.copy(cdexPath, tempCdexIn, StandardCopyOption.REPLACE_EXISTING);
                        DexFile origCdex = DexFileFactory.loadDexFile(tempCdexIn.toFile(), Opcodes.getDefault());
                        DexFile newPatchDex = DexFileFactory.loadDexFile(patchDex.toFile(), Opcodes.getDefault());

                        Set<ClassDef> classes = new HashSet<>();
                        for (ClassDef cd : origCdex.getClasses()) {
                            if (!cd.getType().startsWith("Lapp/morphe/patches/facebook/misc/SignatureCompatibilityPatchKt")) {
                                classes.add(cd);
                            }
                        }
                        for (ClassDef cd : newPatchDex.getClasses()) {
                            classes.add(cd);
                        }

                        ImmutableDexFile finalCdex = new ImmutableDexFile(Opcodes.getDefault(), classes);
                        DexFileFactory.writeDexFile(tempCdexOut.toFile().getAbsolutePath(), finalCdex);
                        Files.copy(tempCdexOut, cdexPath, StandardCopyOption.REPLACE_EXISTING);
                    } finally {
                        Files.deleteIfExists(tempCdexIn);
                        Files.deleteIfExists(tempCdexOut);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Warning: failed to update classes.dex: " + e.getMessage());
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: MppExtensionRewriter <targetPath> <pkgName> [ksPath] [ksPass] [ksAlias]");
            System.exit(1);
        }
        Path targetPath = Paths.get(args[0]);
        String pkgName = args[1];
        String ksPath = args.length > 2 ? args[2] : "";
        String ksPass = args.length > 3 ? args[3] : "";
        String ksAlias = args.length > 4 ? args[4] : "";

        String hash = getKeystoreCertHash(ksPath, ksPass, ksAlias);

        String pathName = targetPath.getFileName().toString().toLowerCase();
        if (pathName.endsWith(".mpe") || pathName.endsWith(".dex")) {
            if (pathName.contains("facebook")) {
                rewriteFacebookDex(targetPath.toFile(), targetPath.toFile(), hash);
            } else if (pathName.contains("extension")) {
                rewriteExtensionDex(targetPath.toFile(), targetPath.toFile());
            } else {
                try {
                    rewriteFacebookDex(targetPath.toFile(), targetPath.toFile(), hash);
                } catch (Exception ignored) {}
                try {
                    rewriteExtensionDex(targetPath.toFile(), targetPath.toFile());
                } catch (Exception ignored) {}
            }
            return;
        }

        URI uri = URI.create("jar:" + targetPath.toUri());
        try (FileSystem fs = FileSystems.newFileSystem(uri, Collections.emptyMap())) {
            Path fbPath = fs.getPath("extensions/facebook.mpe");
            if (Files.exists(fbPath)) {
                Path tempIn = Files.createTempFile("fb_in", ".dex");
                Path tempOut = Files.createTempFile("fb_out", ".dex");
                try {
                    Files.copy(fbPath, tempIn, StandardCopyOption.REPLACE_EXISTING);
                    rewriteFacebookDex(tempIn.toFile(), tempOut.toFile(), hash);
                    Files.copy(tempOut, fbPath, StandardCopyOption.REPLACE_EXISTING);
                } finally {
                    Files.deleteIfExists(tempIn);
                    Files.deleteIfExists(tempOut);
                }
            }

            Path fbPatchClassPath = fs.getPath("app/morphe/patches/facebook/misc/SignatureCompatibilityPatchKt.class");
            if (Files.exists(fbPatchClassPath)) {
                updateFacebookPatchClass(targetPath, fs, fbPatchClassPath);
            }

            Path extPath = fs.getPath("extensions/extension.mpe");
            if (Files.exists(extPath) && ("com.facebook.orca".equals(pkgName) || pkgName.isEmpty())) {
                Path tempIn = Files.createTempFile("ext_in", ".dex");
                Path tempOut = Files.createTempFile("ext_out", ".dex");
                try {
                    Files.copy(extPath, tempIn, StandardCopyOption.REPLACE_EXISTING);
                    rewriteExtensionDex(tempIn.toFile(), tempOut.toFile());
                    Files.copy(tempOut, extPath, StandardCopyOption.REPLACE_EXISTING);
                } finally {
                    Files.deleteIfExists(tempIn);
                    Files.deleteIfExists(tempOut);
                }
            }

            Path patchClassPath = fs.getPath("app/template/patches/messenger/misc/MessengerSignaturePatchKt.class");
            if (Files.exists(patchClassPath)) {
                byte[] bytes = Files.readAllBytes(patchClassPath);
                String str = new String(bytes, java.nio.charset.StandardCharsets.ISO_8859_1);
                if (str.contains("AMIHlR34")) {
                    byte[] replaced = str.replace("AMIHlR34", "AMIH1R34").getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
                    Files.write(patchClassPath, replaced);
                }
            }

            Path classesDexPath = fs.getPath("classes.dex");
            if (Files.exists(classesDexPath) && Files.exists(extPath)) {
                Path tempIn = Files.createTempFile("cdex_in", ".dex");
                Path tempOut = Files.createTempFile("cdex_out", ".dex");
                try {
                    Files.copy(classesDexPath, tempIn, StandardCopyOption.REPLACE_EXISTING);
                    rewriteExtensionDex(tempIn.toFile(), tempOut.toFile());
                    Files.copy(tempOut, classesDexPath, StandardCopyOption.REPLACE_EXISTING);
                } finally {
                    Files.deleteIfExists(tempIn);
                    Files.deleteIfExists(tempOut);
                }
            }
        }
    }
}

"""


class PatcherError(Exception):
    pass

class SignatureError(PatcherError):
    """Raised when sig.txt has no entry for a package, or apksigner reports a hash mismatch."""

def _check_java_ver(bin_path: str) -> int:
    try:
        res = subprocess.run([bin_path, "-version"], capture_output=True, text=True, timeout=5)
        out = (res.stderr or "") + (res.stdout or "")
        if m := re.search(r'version "(\d+)', out):
            return int(m.group(1))
    except Exception:
        pass
    return 0

def _java_bin() -> str:
    global _java_bin_cached
    if _java_bin_cached is not None:
        return _java_bin_cached

    if (sys_java := shutil.which("java")) and _check_java_ver(sys_java) >= 21:
        _java_bin_cached = sys_java
        return _java_bin_cached

    candidates = (
        "/usr/lib/jvm/java-27-openjdk/bin/java",
        "/usr/lib/jvm/java-21-openjdk-amd64/bin/java",
        "/usr/lib/jvm/java-21-openjdk/bin/java",
    )
    for c in candidates:
        if Path(c).is_file() and _check_java_ver(c) >= 21:
            _java_bin_cached = c
            return _java_bin_cached

    jvm_dir = Path("/usr/lib/jvm")
    if jvm_dir.is_dir():
        for j in sorted(jvm_dir.glob("java-2*/bin/java"), reverse=True):
            if j.is_file() and _check_java_ver(str(j)) >= 21:
                _java_bin_cached = str(j)
                return _java_bin_cached

    _java_bin_cached = sys_java or "java"
    return _java_bin_cached

def _ensure_helper_java() -> Path:
    global _java_helper_path
    if _java_helper_path is not None and _java_helper_path.is_file():
        return _java_helper_path

    cache_dir = Path(tempfile.gettempdir()) / "morphe_ext_rewriter_v4"
    cache_dir.mkdir(parents=True, exist_ok=True)
    helper_path = cache_dir / "MppExtensionRewriter.java"
    helper_path.write_text(_REWRITER_JAVA_SOURCE.strip(), encoding="utf-8")
    _java_helper_path = helper_path
    return _java_helper_path

def _run_java(*args: str | Path, capture: bool = True, timeout: int = 600) -> str:
    result = subprocess.run([_java_bin(), *(str(a) for a in args)], capture_output=capture, text=True, timeout=timeout)
    combined = (result.stdout or "") + (result.stderr or "")
    if result.returncode != 0:
        redacted = _SECRET_PATTERNS.sub(r"\1***", combined)
        raise PatcherError(redacted.strip())
    return combined

def _parse_patch_block(output: str, patch_name: str, pkg_name: str) -> list[str]:
    pattern = rf"Name:\s*{re.escape(patch_name)}\n.*?Package name:\s*{re.escape(pkg_name)}\s*\n\s*Compatible versions:\s*\n(.*?)(?:\n\s*Package name:|\n\s*Version codes:|\n\n|\Z)"
    if m := re.search(pattern, output, re.DOTALL | re.IGNORECASE):
        return [v.strip() for v in m.group(1).splitlines() if v.strip()]
    return []

def _parse_versions_output(output: str) -> list[str]:
    marker = "Most common compatible versions:\n"
    if marker not in output:
        return []

    block = output.split(marker)[1].split("\n\n")[0]
    versions: list[str] = []
    for line in block.splitlines():
        parts = line.split()
        if parts:
            versions.append(parts[0])
    return versions

def _extract_version_code(output: str, version: str, arch: str) -> str | None:
    arch_map = {
        "arm64-v8a": "ARM64_V8A", "armeabi-v7a": "ARMEABI_V7A", 
        "x86": "X86", "x86_64": "X86_64"
    }
    target_arch = arch_map.get(arch.lower(), "ARM64_V8A")
    if m := re.search(rf"{re.escape(version)}.*?{target_arch}=(\d+)", output, re.IGNORECASE):
        return m.group(1)
    return None

def _redact_args(args: list[str | Path]) -> list[str]:
    return [_SECRET_PATTERNS.sub(r"\1***", str(a)) for a in args]

class PatcherCLI:
    def __init__(self, cli_jar: Path, mpp_map: dict[tuple[str, str], Path], apksigner: Path, ks_path: Path | None = None, sig_file: Path = Path("sig.txt")) -> None:
        self.cli_jar = cli_jar
        self.mpp_map = mpp_map.copy()
        self.apksigner = apksigner
        self.ks_path = ks_path
        self._last_pkg_name: str = ""
        self._last_list_patches: str = ""
        self._rewritten_mpps: set[tuple[Path, str]] = set()
        self._signatures: dict[str, str] = {}
        if sig_file.exists():
            for line in sig_file.read_text(encoding="utf-8").splitlines():
                if parts := line.split():
                    self._signatures[parts[-1]] = parts[0].lower()

    def has_signature(self, pkg_name: str) -> bool:
        expected = self._signatures.get(pkg_name)
        return bool(expected)

    def _run_rewriter(self, target_path: Path, pkg_name: str = "") -> None:
        helper = _ensure_helper_java()
        ks_path = str(self.ks_path) if self.ks_path and self.ks_path.exists() else ("morphe.keystore" if Path("morphe.keystore").exists() else "")
        ks_pass = os.getenv("KEYSTORE_PASS", "")
        ks_alias = os.getenv("KEYSTORE_ALIAS", "Morphe")
        _run_java("-cp", self.cli_jar, helper, target_path, pkg_name, ks_path, ks_pass, ks_alias)

    def rewrite_mpe(self, mpe_path: Path, pkg_name: str = "") -> Path:
        self._run_rewriter(mpe_path, pkg_name)
        return mpe_path

    def rewrite_mpp(self, mpp_path: Path, pkg_name: str = "") -> Path:
        self._run_rewriter(mpp_path, pkg_name)
        return mpp_path

    def ensure_mpp_compatibility(self, pkg_name: str = "") -> None:
        target_pkg = pkg_name or self._last_pkg_name
        for key, mpp_path in list(self.mpp_map.items()):
            if not mpp_path.is_file():
                continue
            if (mpp_path, target_pkg) in self._rewritten_mpps:
                continue

            try:
                with zipfile.ZipFile(mpp_path, "r") as zf:
                    names = set(zf.namelist())
            except Exception:
                continue

            needs_fb = "extensions/facebook.mpe" in names
            needs_ext = "extensions/extension.mpe" in names and (target_pkg == "com.facebook.orca")
            if not (needs_fb or needs_ext):
                self._rewritten_mpps.add((mpp_path, target_pkg))
                continue

            copy_suffix = f"-{target_pkg}.mpp" if target_pkg else "-compat.mpp"
            rewritten_mpp = mpp_path.with_name(f"{mpp_path.stem}{copy_suffix}")
            if not rewritten_mpp.exists() or rewritten_mpp.stat().st_mtime < mpp_path.stat().st_mtime:
                shutil.copyfile(mpp_path, rewritten_mpp)
                self._run_rewriter(rewritten_mpp, target_pkg)

            self.mpp_map[key] = rewritten_mpp
            self._rewritten_mpps.add((rewritten_mpp, target_pkg))
            self._rewritten_mpps.add((mpp_path, target_pkg))

    def list_patches(self, pkg_name: str, experimental: bool = False) -> str:
        self._last_pkg_name = pkg_name
        self.ensure_mpp_compatibility(pkg_name)
        extra = ["-x"] if experimental else []
        output = "".join(_run_java("-jar", self.cli_jar, "list-patches", "--patches", mpp, "-f", pkg_name, "-v", "-p", *extra, timeout=60) for mpp in self.mpp_map.values())
        self._last_list_patches = output
        return output

    def list_versions(self, pkg_name: str, experimental: bool = False) -> str:
        self._last_pkg_name = pkg_name
        extra = ["-x"] if experimental else []
        parts: list[str] = []
        for mpp in self.mpp_map.values():
            with contextlib.suppress(PatcherError):
                parts.append(_run_java("-jar", self.cli_jar, "list-versions", "--patches", mpp, "-f", pkg_name, *extra, timeout=60))
        return "\n".join(parts)

    def get_last_supported_version(self, list_patches_output: str, pkg_name: str, patches: dict[str, PatchSpec], arch: str = "arm64-v8a", experimental: bool = False) -> tuple[str, str | None] | None:
        all_included = [p for spec in patches.values() for p in spec["include"]]
        all_vers: list[str] = []
        for p in all_included:
            all_vers.extend(_parse_patch_block(list_patches_output, p, pkg_name))
        if all_vers:
            highest = get_highest_ver(all_vers)
            return (highest, _extract_version_code(list_patches_output, highest, arch)) if highest else None

        versions_output = self.list_versions(pkg_name, experimental)
        if "Any" in versions_output:
            return None

        if not (versions := _parse_versions_output(versions_output)):
            if list_patches_output.strip():
                return None
            raise PatcherError(f"No patches found for '{pkg_name}'")
        highest = get_highest_ver(versions)
        return (highest, _extract_version_code(versions_output, highest, arch)) if highest else None

    def resolve_auto_patches(self, list_patches_output: str, pkg_name: str = "") -> list[str]:
        target_pkg = (pkg_name or getattr(self, "_last_pkg_name", "")).strip().lower()
        if "Index:" in list_patches_output:
            blocks = [b.strip() for b in re.split(r"(?:\r?\n)+(?=Index:\s*\d+)", list_patches_output) if b.strip()]
        else:
            blocks = [b.strip() for b in re.split(r"(?:\r?\n){2,}", list_patches_output) if b.strip()]

        microg_patch = psu_patch = ""
        for block in blocks:
            if target_pkg and target_pkg not in block.lower():
                continue

            for line in block.splitlines():
                line_lower = line.lower()
                if not line_lower.startswith("name:"):
                    continue

                patch_name = line[5:].strip()
                name_lower = patch_name.lower()
                if "gmscore" in name_lower or "microg" in name_lower:
                    microg_patch = patch_name
                elif "disable play store updates" in name_lower:
                    psu_patch = patch_name
        return [p for p in (microg_patch, psu_patch) if p]

    def build_patch_args(
        self,
        patches: dict[str, PatchSpec],
        extra_args: list[str],
        arch: str,
        auto_patches: tuple[str, ...] | list[str] = (),
        exclusive: bool = False,
        force: bool = False,
        pkg_name: str = "",
        lp_out: str = "",
    ) -> list[str]:
        target_pkg = pkg_name or getattr(self, "_last_pkg_name", "")
        if target_pkg:
            self.ensure_mpp_compatibility(target_pkg)

        if lp_out:
            auto_patches = self.resolve_auto_patches(lp_out, pkg_name=target_pkg)
        elif not auto_patches and target_pkg and hasattr(self, "_last_list_patches") and self._last_list_patches:
            auto_patches = self.resolve_auto_patches(self._last_list_patches, pkg_name=target_pkg)

        all_excludes = {x.lower() for spec in patches.values() for x in spec["exclude"]}
        active_auto = {p for p in auto_patches if p and p.lower() not in all_excludes}
        p_args: list[str] = ["-f"] if force else []
        for src, spec in patches.items():
            p_args.extend(("--patches", str(self.mpp_map[(src, spec["version"])])))
            for p in spec["include"]:
                if p in active_auto:
                    wpr(f"You can't include '{p}' patch as that's done by builder automatically")
                else:
                    p_args.extend(("-e", p))
            for p in spec["exclude"]:
                p_args.extend(("-d", p))
        if exclusive:
            p_args.append("--exclusive")

        p_args.extend(extra_args)
        for auto_p in active_auto:
            p_args.extend(("-e", auto_p))
        p_args.extend(("--striplibs", "arm64-v8a,armeabi-v7a" if arch == "all" else arch))

        formatted_args: list[str] = []
        for arg in p_args:
            if arg.startswith("-O") and "=" in arg:
                opt, val = arg.split("=", 1)
                if val.isdigit() and not (val.startswith(('"', "'")) and val.endswith(('"', "'"))):
                    formatted_args.append(f'{opt}="{val}"')
                    continue
            formatted_args.append(arg)

        if "--continue-on-error" not in formatted_args:
            formatted_args.append("--continue-on-error")

        return formatted_args

    def patch(self, stock_apk: Path, output_apk: Path, patch_args: list[str]) -> None:
        base_cmd = ["-jar", self.cli_jar, "patch", stock_apk, "-o", output_apk]
        ks_args: list[str] = []
        if self.ks_path and (ks_alias := os.getenv("KEYSTORE_ALIAS")):
            ks_args = [f"--keystore={self.ks_path}", f"--signer={ks_alias}", f"--keystore-entry-alias={ks_alias}"]
            entry_pass = os.getenv("KEYSTORE_ENTRY_PASS") or os.getenv("KEYSTORE_PASS") or ""
            store_pass = os.getenv("KEYSTORE_PASSWORD") or os.getenv("KEYSTORE_PASS") or ""
            if entry_pass:
                ks_args.append(f"--keystore-entry-password={entry_pass}")
            if store_pass:
                ks_args.append(f"--keystore-password={store_pass}")
        elif Path("morphe.keystore").exists():
            ks_args = ["--keystore=morphe.keystore"]

        pr(" ".join(_redact_args([_java_bin(), *base_cmd, *ks_args, *patch_args])))
        try:
            _run_java(*base_cmd, *ks_args, *patch_args, capture=False)
        except subprocess.TimeoutExpired:
            output_apk.unlink(missing_ok=True)
            raise PatcherError(f"Patching '{stock_apk.name}' failed, process timed out after 10 minutes") from None
        except PatcherError as exc:
            output_apk.unlink(missing_ok=True)
            raise PatcherError(f"Patching '{stock_apk.name}' failed:\n{exc}") from exc

    def check_signature(self, apk: Path, pkg_name: str) -> bool:
        expected = self._signatures.get(pkg_name)
        if not expected:
            return True

        try:
            output = _run_java("--enable-native-access=ALL-UNNAMED", "-jar", self.apksigner, "verify", "--print-certs", apk)
            return expected.lower() in output.lower()
        except PatcherError:
            return False
