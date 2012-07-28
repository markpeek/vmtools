/*
 * Copyright (c) 2011-2012, Mark Peek <mark@peek.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met: 
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer. 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define PY_SSIZE_T_CLEAN
#include <stdio.h>
#include <stdint.h>
#include <Python.h>
#include "structmember.h"

typedef union {
    struct {
        uint16_t low;
        uint16_t high;
    } words;
    uint32_t dword;
#if __amd64__
    struct {
        uint32_t low;
        uint32_t high;
    } dwords;
    uint64_t qword;
#endif
} x86_register_t;

typedef struct {
    x86_register_t rax;
    x86_register_t rbx;
    x86_register_t rcx;
    x86_register_t rdx;
    x86_register_t rsi;
    x86_register_t rdi;
    x86_register_t rbp;
} x86_registers_t;

#ifdef __amd64__
void
vmware_backdoor(x86_registers_t *regs)
{
   __asm__ __volatile__(
        "pushq %%rbp"           "\n\t"
        "pushq %%rax"           "\n\t"
        "movq 48(%%rax), %%rbp" "\n\t"
        "movq 40(%%rax), %%rdi" "\n\t"
        "movq 32(%%rax), %%rsi" "\n\t"
        "movq 24(%%rax), %%rdx" "\n\t"
        "movq 16(%%rax), %%rcx" "\n\t"
        "movq  8(%%rax), %%rbx" "\n\t"
        "movq   (%%rax), %%rax" "\n\t"
        "inl %%dx, %%eax"       "\n\t"
        "xchgq %%rax, (%%rsp)"  "\n\t"
        "movq %%rbp, 48(%%rax)" "\n\t"
        "movq %%rdi, 40(%%rax)" "\n\t"
        "movq %%rsi, 32(%%rax)" "\n\t"
        "movq %%rdx, 24(%%rax)" "\n\t"
        "movq %%rcx, 16(%%rax)" "\n\t"
        "movq %%rbx,  8(%%rax)" "\n\t"
        "popq 0x00(%%rax)"      "\n\t"
        "popq %%rbp"            "\n\t"
      : : "a" (regs) : "rbx", "rcx", "rdx", "rsi", "rdi", "cc", "memory"
   );
}

void
vmware_backdoor_recv(x86_registers_t *regs)
{
   __asm__ __volatile__(
        "pushq %%rbp"           "\n\t"
        "pushq %%rax"           "\n\t"
        "movq 48(%%rax), %%rbp" "\n\t"
        "movq 40(%%rax), %%rdi" "\n\t"
        "movq 32(%%rax), %%rsi" "\n\t"
        "movq 24(%%rax), %%rdx" "\n\t"
        "movq 16(%%rax), %%rcx" "\n\t"
        "movq  8(%%rax), %%rbx" "\n\t"
        "movq   (%%rax), %%rax" "\n\t"
        "cld"                   "\n\t"
        "rep insb"              "\n\t"
        "xchgq %%rax, (%%rsp)"  "\n\t"
        "movq %%rbp, 48(%%rax)" "\n\t"
        "movq %%rdi, 40(%%rax)" "\n\t"
        "movq %%rsi, 32(%%rax)" "\n\t"
        "movq %%rdx, 24(%%rax)" "\n\t"
        "movq %%rcx, 16(%%rax)" "\n\t"
        "movq %%rbx,  8(%%rax)" "\n\t"
        "popq 0x00(%%rax)"      "\n\t"
        "popq %%rbp"            "\n\t"
      : : "a" (regs) : "rbx", "rcx", "rdx", "rsi", "rdi", "cc", "memory"
   );
}

void
vmware_backdoor_send(x86_registers_t *regs)
{
   __asm__ __volatile__(
        "pushq %%rbp"           "\n\t"
        "pushq %%rax"           "\n\t"
        "movq 48(%%rax), %%rbp" "\n\t"
        "movq 40(%%rax), %%rdi" "\n\t"
        "movq 32(%%rax), %%rsi" "\n\t"
        "movq 24(%%rax), %%rdx" "\n\t"
        "movq 16(%%rax), %%rcx" "\n\t"
        "movq  8(%%rax), %%rbx" "\n\t"
        "movq   (%%rax), %%rax" "\n\t"
        "cld"                   "\n\t"
        "rep outsb"             "\n\t"
        "xchgq %%rax, (%%rsp)"  "\n\t"
        "movq %%rbp, 48(%%rax)" "\n\t"
        "movq %%rdi, 40(%%rax)" "\n\t"
        "movq %%rsi, 32(%%rax)" "\n\t"
        "movq %%rdx, 24(%%rax)" "\n\t"
        "movq %%rcx, 16(%%rax)" "\n\t"
        "movq %%rbx,  8(%%rax)" "\n\t"
        "popq 0x00(%%rax)"      "\n\t"
        "popq %%rbp"            "\n\t"
      : : "a" (regs) : "rbx", "rcx", "rdx", "rsi", "rdi", "cc", "memory"
   );
}
#else
void
vmware_backdoor(x86_registers_t *regs)
{
   __asm__ __volatile__(
        "pushl %%ebx"           "\n\t"
        "pushl %%esi"           "\n\t"
        "pushl %%edi"           "\n\t"
        "pushl %%ebp"           "\n\t"
        "pushl %%eax"           "\n\t"
        "movl 24(%%eax), %%ebp" "\n\t"
        "movl 20(%%eax), %%edi" "\n\t"
        "movl 16(%%eax), %%esi" "\n\t"
        "movl 12(%%eax), %%edx" "\n\t"
        "movl  8(%%eax), %%ecx" "\n\t"
        "movl  4(%%eax), %%ebx" "\n\t"
        "movl   (%%eax), %%eax" "\n\t"
        "inl %%dx, %%eax"       "\n\t"
        "xchgl %%eax, (%%esp)"  "\n\t"
        "movl %%ebp, 24(%%eax)" "\n\t"
        "movl %%edi, 20(%%eax)" "\n\t"
        "movl %%esi, 16(%%eax)" "\n\t"
        "movl %%edx, 12(%%eax)" "\n\t"
        "movl %%ecx,  8(%%eax)" "\n\t"
        "movl %%ebx,  4(%%eax)" "\n\t"
        "popl %%eax"          "\n\t"
        "popl %%ebp"          "\n\t"
        "popl %%edi"          "\n\t"
        "popl %%esi"          "\n\t"
        "popl %%ebx"          "\n\t"
      : : "a" (regs) : "ecx", "edx", "cc", "memory"
   );
}

void
vmware_backdoor_recv(x86_registers_t *regs)
{
   __asm__ __volatile__(
        "pushl %%ebx"           "\n\t"
        "pushl %%esi"           "\n\t"
        "pushl %%edi"           "\n\t"
        "pushl %%ebp"           "\n\t"
        "pushl %%eax"           "\n\t"
        "movl 24(%%eax), %%ebp" "\n\t"
        "movl 20(%%eax), %%edi" "\n\t"
        "movl 16(%%eax), %%esi" "\n\t"
        "movl 12(%%eax), %%edx" "\n\t"
        "movl  8(%%eax), %%ecx" "\n\t"
        "movl  4(%%eax), %%ebx" "\n\t"
        "movl   (%%eax), %%eax" "\n\t"
        "cld"                   "\n\t"
        "rep insb"              "\n\t"
        "xchgl %%eax, (%%esp)"  "\n\t"
        "movl %%ebp, 24(%%eax)" "\n\t"
        "movl %%edi, 20(%%eax)" "\n\t"
        "movl %%esi, 16(%%eax)" "\n\t"
        "movl %%edx, 12(%%eax)" "\n\t"
        "movl %%ecx,  8(%%eax)" "\n\t"
        "movl %%ebx,  4(%%eax)" "\n\t"
        "popl %%eax"          "\n\t"
        "popl %%ebp"          "\n\t"
        "popl %%edi"          "\n\t"
        "popl %%esi"          "\n\t"
        "popl %%ebx"          "\n\t"
      : : "a" (regs) : "ecx", "edx", "cc", "memory"
   );
}

void
vmware_backdoor_send(x86_registers_t *regs)
{
   __asm__ __volatile__(
        "pushl %%ebx"           "\n\t"
        "pushl %%esi"           "\n\t"
        "pushl %%edi"           "\n\t"
        "pushl %%ebp"           "\n\t"
        "pushl %%eax"           "\n\t"
        "movl 24(%%eax), %%ebp" "\n\t"
        "movl 20(%%eax), %%edi" "\n\t"
        "movl 16(%%eax), %%esi" "\n\t"
        "movl 12(%%eax), %%edx" "\n\t"
        "movl  8(%%eax), %%ecx" "\n\t"
        "movl  4(%%eax), %%ebx" "\n\t"
        "movl   (%%eax), %%eax" "\n\t"
        "cld"                   "\n\t"
        "rep outsb"              "\n\t"
        "xchgl %%eax, (%%esp)"  "\n\t"
        "movl %%ebp, 24(%%eax)" "\n\t"
        "movl %%edi, 20(%%eax)" "\n\t"
        "movl %%esi, 16(%%eax)" "\n\t"
        "movl %%edx, 12(%%eax)" "\n\t"
        "movl %%ecx,  8(%%eax)" "\n\t"
        "movl %%ebx,  4(%%eax)" "\n\t"
        "popl %%eax"          "\n\t"
        "popl %%ebp"          "\n\t"
        "popl %%edi"          "\n\t"
        "popl %%esi"          "\n\t"
        "popl %%ebx"          "\n\t"
      : : "a" (regs) : "ecx", "edx", "cc", "memory"
   );
}
#endif

typedef struct {
    PyObject_HEAD
    x86_registers_t regs;
} vmtobject;

static PyTypeObject vmttype;

#if 0
static PyObject *
vmt_alloc(PyTypeObject *type, Py_ssize_t nitems)
{
    PyObject *obj;

    obj = PyType_GenericAlloc(type, nitems);
    return obj;
}

static PyObject *
vmt_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    vmtobject *self;

    self = (vmtobject *)type->tp_alloc(type, 0);
    if (self != NULL) {
        Py_INCREF(self);
        self->regs.rax.dword = 0;
        self->regs.rbx.dword = 0;
        self->regs.rcx.dword = 0;
        self->regs.rdx.dword = 0;
        self->regs.rsi.dword = 0;
        self->regs.rdi.dword = 0;
        self->regs.rbp.dword = 0;
    }

    return (PyObject *)self;
}

static int
vmt_init(vmtobject *self, PyObject *args, PyObject *keywds)
{
    uint32_t rax, rbx, rcx, rdx, rsi, rdi, rbp;
    static char *kwlist[] =
        { "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", NULL };

    /* lazy assignment...lol */
    rax = rbx = rcx = rdx = rsi = rdi = rbp = 0;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "|iiiiiii:new", kwlist,
        &rax, &rbx, &rcx, &rdx, &rsi, &rdi, &rbp))
        return -1;

    self->regs.rax.dword = rax;
    self->regs.rbx.dword = rbx;
    self->regs.rcx.dword = rcx;
    self->regs.rdx.dword = rdx;
    self->regs.rsi.dword = rsi;
    self->regs.rdi.dword = rdi;
    self->regs.rbp.dword = rbp;

    return 0;
}
#endif

static int
vmt_init(vmtobject *self, PyObject *args, PyObject *keywds)
{
    uint32_t rax, rbx, rcx, rdx, rsi, rdi, rbp;
    static char *kwlist[] =
        { "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", NULL };

    /* lazy assignment...lol */
    rax = rbx = rcx = rdx = rsi = rdi = rbp = 0;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "|iiiiiii:new", kwlist,
        &rax, &rbx, &rcx, &rdx, &rsi, &rdi, &rbp))
        return -1;

    self->regs.rax.dword = rax;
    self->regs.rbx.dword = rbx;
    self->regs.rcx.dword = rcx;
    self->regs.rdx.dword = rdx;
    self->regs.rsi.dword = rsi;
    self->regs.rdi.dword = rdi;
    self->regs.rbp.dword = rbp;

    return 0;
}

static void
vmt_dealloc(vmtobject *self)
{
    Py_TYPE(self)->tp_free(self);
}

static PyObject *
vmt_repr(vmtobject *vmtp)
{
        char buf[512];

        PyOS_snprintf(
                buf, sizeof(buf),
                "<vmt object rax=0x%x rbx=0x%x rcx=0x%x rdx=0x%x "
                "rsi=0x%x rdi=0x%x rbp=0x%x>",
                vmtp->regs.rax.dword, vmtp->regs.rbx.dword,
                vmtp->regs.rcx.dword, vmtp->regs.rdx.dword,
                vmtp->regs.rsi.dword, vmtp->regs.rdi.dword,
                vmtp->regs.rbp.dword);
        return PyString_FromString(buf);
}

static PyMethodDef vmt_functions[] = {
        {NULL,      NULL}   /* Sentinel */
};

PyDoc_STRVAR(module_doc, "Document this module here...\n");

static PyObject *
vmt_backdoor(vmtobject *self)
{
    vmware_backdoor(&self->regs);

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
vmt_backdoor_recv(vmtobject *self, PyObject *args)
{
    PyObject *o;
    char *s;
    Py_ssize_t n = 0; /* XXX - shouldn't need to do this */

    if (!PyArg_ParseTuple(args, "i", &n))
        return NULL;

    /* Allocate space to receive the buffer */
    s = malloc(n);
    if (s == NULL)
        return NULL;

#if __amd64__
    self->regs.rdi.qword = (uint64_t)s;
#else
    self->regs.rdi.dword = (uint32_t)s;
#endif
    vmware_backdoor_recv(&self->regs);

    o = PyString_FromStringAndSize(s, n);
    free(s);
    return o;
}

static PyObject *
vmt_backdoor_send(vmtobject *self, PyObject *args)
{
    char *s;
    Py_ssize_t n;

    if (!PyArg_ParseTuple(args, "s#", &s, &n))
        return NULL;

#if __amd64__
    self->regs.rsi.qword = (uint64_t)s;
#else
    self->regs.rsi.dword = (uint32_t)s;
#endif

    vmware_backdoor_send(&self->regs);

    Py_INCREF(Py_None);
    return Py_None;
}


static PyMethodDef vmt_methods[] = {
    {"backdoor",      (PyCFunction)vmt_backdoor,      METH_NOARGS,  NULL},
    {"backdoor_recv", (PyCFunction)vmt_backdoor_recv, METH_VARARGS,  NULL},
    {"backdoor_send", (PyCFunction)vmt_backdoor_send, METH_VARARGS,  NULL},
    {NULL, NULL}
};

static PyMemberDef vmt_members[] = {
    {"rax", T_UINT, offsetof(vmtobject, regs.rax.dword), 0, "rax register" },
    {"rbx", T_UINT, offsetof(vmtobject, regs.rbx.dword), 0, "rbx register" },
    {"rcx", T_UINT, offsetof(vmtobject, regs.rcx.dword), 0, "rcx register" },
    {"rdx", T_UINT, offsetof(vmtobject, regs.rdx.dword), 0, "rdx register" },
    {"rsi", T_UINT, offsetof(vmtobject, regs.rsi.dword), 0, "rsi register" },
    {"rdi", T_UINT, offsetof(vmtobject, regs.rdi.dword), 0, "rdi register" },
    {"rbp", T_UINT, offsetof(vmtobject, regs.rbp.dword), 0, "rbp register" },
    {NULL}
};

static PyTypeObject vmttype = {
        PyObject_HEAD_INIT(NULL)
        0,                        /*ob_size*/
        "_vmt.vmt",               /*tp_name*/
        sizeof(vmtobject),        /*tp_size*/
        0,                        /*tp_itemsize*/
        /* methods */
        (destructor)vmt_dealloc,  /*tp_dealloc*/
        0,                        /*tp_print*/
        0,                        /*tp_getattr*/
        0,                        /*tp_setattr*/
        0,                        /*tp_compare*/
        (reprfunc)vmt_repr,       /*tp_repr*/
        0,                        /*tp_as_number*/
        0,                        /*tp_as_sequence*/
        0,                        /*tp_as_mapping*/
        0,                        /*tp_hash*/
        0,                        /*tp_call*/
        0,                        /*tp_str*/
        0,                        /*tp_getattro*/
        0,                        /*tp_setattro*/
        0,                        /*tp_as_buffer*/
        Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE|Py_TPFLAGS_HEAPTYPE,       /*tp_flags*/
        "vmt object",             /*tp_doc*/
        0,                        /*tp_traverse*/
        0,                        /*tp_clear*/
        0,                        /*tp_richcompare*/
        0,                        /*tp_weaklistoffset*/
        0,                        /*tp_iter*/
        0,                        /*tp_iternext*/
        vmt_methods,              /*tp_methods*/
        vmt_members,              /*tp_members*/
        0,                        /*tp_getset*/
        0,                        /* tp_base */
        0,                        /* tp_dict */
        0,                        /* tp_descr_get */
        0,                        /* tp_descr_set */
        0,                        /* tp_dictoffset */
        (initproc)vmt_init,       /* tp_init */
        0,      /* tp_alloc */
        0,        /* tp_new */
        0,            /* tp_free */
};

PyMODINIT_FUNC
init_vmt(void)
{
        PyObject *m;

        /*Py_TYPE(&vmttype) = &PyType_Type;*/
        if (PyType_Ready(&vmttype) < 0)
            return;

        m = Py_InitModule3("_vmt", vmt_functions, module_doc);
        if (m == NULL)
            return;

        Py_INCREF(&vmttype);
        PyModule_AddObject(m, "vmt", (PyObject *)&vmttype);

        PyModule_AddIntConstant(m, "VM_BACKDOOR_PORT", 0x5658);
        PyModule_AddIntConstant(m, "VM_RPC_PORT", 0x5659);
        PyModule_AddIntConstant(m, "VM_MAGIC", 0x564D5868);
        PyModule_AddIntConstant(m, "VM_GET_SPEED", 0x01);
        PyModule_AddIntConstant(m, "VM_GET_VERSION", 0x0a);
        PyModule_AddIntConstant(m, "VM_GET_UUID", 0x13);
        PyModule_AddIntConstant(m, "VM_GET_MEMSIZE", 0x14);
        PyModule_AddIntConstant(m, "VM_CMD", 0x1e);
        PyModule_AddIntConstant(m, "VM_GET_TIME_FULL", 0x2e);
}
